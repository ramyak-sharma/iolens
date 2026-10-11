// SPDX-License-Identifier: GPL-2.0
/* iolens: per request block io latency, split in queue and device time,
 * kept as histograms per (cgroup, device, op). nothing goes to user space
 * per request, the agent just reads the hists map once a second. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "iolens.h"

char LICENSE[] SEC("license") = "GPL";

/* REQ_OP_MASK in include/linux/blk_types.h, op is low 8 bits of cmd_flags */
#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)
#define MINORBITS 20

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); /* struct request pointer */
	__type(value, struct inflight_req);
} inflight SEC(".maps");

/* not percpu on purpose: 1.7KB * 4096 keys * every cpu is way too much
 * memory. cost is cache line bouncing on the atomics, V4 measures it */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 4096);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

/* struct hist is way bigger than 512 byte stack so new entries get copied
 * from this zeroed template */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct hist);
} zero SEC(".maps");

/* must match hist.Index in internal/hist/hist.go:
 *   0..3 -> 0..3, 4 -> 4, 8 -> 8, 9 -> 8, 10 -> 9, 1023 -> 35, 1024 -> 36,
 *   2^25 -> 96, anything >= 2^26 -> 99 */
static __always_inline __u32 bucket_index(__u64 us)
{
	__u32 order = 0;
	int i;

	if (us > MAX_US)
		us = MAX_US;
	if (us < SUB)
		return us;

	/* highest set bit, bounded so verifier is happy */
	for (i = MAX_ORDER; i > 0; i--) {
		if (us >> i) {
			order = i;
			break;
		}
	}
	return (order - 1) * SUB + ((us >> (order - SUB_BITS)) & (SUB - 1));
}

static __always_inline __u8 req_op(struct request *rq)
{
	__u32 flags = BPF_CORE_READ(rq, cmd_flags);

	switch (flags & REQ_OP_MASK) {
	case REQ_OP_READ:
		return IOLENS_OP_READ;
	case REQ_OP_WRITE:
		return IOLENS_OP_WRITE;
	case REQ_OP_FLUSH:
		return IOLENS_OP_FLUSH;
	case REQ_OP_DISCARD:
		return IOLENS_OP_DISCARD;
	}
	return IOLENS_OP_OTHER;
}

static __always_inline __u32 req_dev(struct request *rq)
{
	struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
	__u32 major, minor;

	if (!disk)
		return 0;
	major = BPF_CORE_READ(disk, major);
	minor = BPF_CORE_READ(disk, first_minor);
	return (major << MINORBITS) | minor;
}

/* the cgroup the io is charged to, not whoever is running right now.
 * writeback and plugging mean the issuing task is often a kworker, but
 * bio->bi_blkg points at the blkcg that dirtied the pages. same thing the
 * kernels own io controller uses */
static __always_inline __u64 req_cgroup(struct request *rq)
{
	struct bio *bio;
	struct blkcg_gq *blkg;
	struct cgroup *cg;

	if (!bpf_core_field_exists(struct bio, bi_blkg))
		return 0;
	bio = BPF_CORE_READ(rq, bio);
	if (!bio)
		return 0;
	blkg = BPF_CORE_READ(bio, bi_blkg);
	if (!blkg)
		return 0;
	cg = BPF_CORE_READ(blkg, blkcg, css.cgroup);
	if (!cg)
		return 0;
	return BPF_CORE_READ(cg, kn, id);
}

static __always_inline void track(struct request *rq, bool inserted)
{
	__u64 key = (__u64)rq;
	__u64 now = bpf_ktime_get_ns();
	struct inflight_req *f, fresh = {};

	f = bpf_map_lookup_elem(&inflight, &key);
	if (f) {
		/* issue after insert, or a requeue. requeue just moves issue_ns */
		if (inserted)
			f->insert_ns = now;
		else
			f->issue_ns = now;
		if (!f->cgid)
			f->cgid = req_cgroup(rq);
		if (!inserted) {
			f->bytes = BPF_CORE_READ(rq, __data_len);
			f->op = req_op(rq);
		}
		return;
	}

	fresh.cgid = req_cgroup(rq);
	if (!fresh.cgid)
		/* flushes and internal commands have no bio, best effort */
		fresh.cgid = bpf_get_current_cgroup_id();
	if (inserted) {
		fresh.insert_ns = now;
	} else {
		fresh.issue_ns = now;
		fresh.bytes = BPF_CORE_READ(rq, __data_len);
		fresh.op = req_op(rq);
	}
	bpf_map_update_elem(&inflight, &key, &fresh, BPF_ANY);
}

SEC("tp_btf/block_rq_insert")
int BPF_PROG(on_insert, struct request *rq)
{
	track(rq, true);
	return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(on_issue, struct request *rq)
{
	track(rq, false);
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(on_complete, struct request *rq, int error, unsigned int nr_bytes)
{
	__u64 key = (__u64)rq;
	__u64 now = bpf_ktime_get_ns();
	__u64 dev_ns, tot_ns, queue_ns;
	struct inflight_req *f;
	struct hist_key hk = {};
	struct hist *h;
	__u32 zk = 0;
	__u32 di, ti;

	/* tracepoint fires from blk_update_request, which can be a partial
	 * completion. only count the last piece, when nothing is left */
	if (nr_bytes < BPF_CORE_READ(rq, __data_len))
		return 0;

	f = bpf_map_lookup_elem(&inflight, &key);
	if (!f)
		return 0; /* started before we attached */
	if (!f->issue_ns) {
		bpf_map_delete_elem(&inflight, &key);
		return 0;
	}

	dev_ns = now - f->issue_ns;
	tot_ns = f->insert_ns ? now - f->insert_ns : dev_ns;
	queue_ns = tot_ns - dev_ns;

	hk.cgid = f->cgid;
	hk.dev = req_dev(rq);
	hk.op = f->op;
	__u32 bytes = f->bytes;
	bpf_map_delete_elem(&inflight, &key);

	h = bpf_map_lookup_elem(&hists, &hk);
	if (!h) {
		struct hist *z = bpf_map_lookup_elem(&zero, &zk);
		if (!z)
			return 0;
		bpf_map_update_elem(&hists, &hk, z, BPF_NOEXIST);
		h = bpf_map_lookup_elem(&hists, &hk);
		if (!h)
			return 0; /* map full */
	}

	di = bucket_index(dev_ns / 1000);
	ti = bucket_index(tot_ns / 1000);
	if (di >= NUM_SLOTS)
		di = NUM_SLOTS - 1;
	if (ti >= NUM_SLOTS)
		ti = NUM_SLOTS - 1;

	__sync_fetch_and_add(&h->dev_slots[di], 1);
	__sync_fetch_and_add(&h->tot_slots[ti], 1);
	__sync_fetch_and_add(&h->count, 1);
	__sync_fetch_and_add(&h->bytes, bytes);
	__sync_fetch_and_add(&h->queue_ns, queue_ns);
	__sync_fetch_and_add(&h->dev_ns, dev_ns);
	__sync_fetch_and_add(&h->tot_ns, tot_ns);
	if (error)
		__sync_fetch_and_add(&h->errors, 1);
	return 0;
}
