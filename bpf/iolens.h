/* shared between iolens.bpf.c and the go side (through bpf2go types).
 * if you change a struct here, run make generate */
#ifndef IOLENS_H
#define IOLENS_H

#define SUB_BITS   2
#define SUB        (1 << SUB_BITS)
#define MAX_ORDER  25
#define NUM_SLOTS  ((MAX_ORDER - 1) * SUB + SUB) /* 100 */
#define MAX_US     ((1ULL << (MAX_ORDER + 1)) - 1)

enum iolens_op {
	IOLENS_OP_READ = 0,
	IOLENS_OP_WRITE = 1,
	IOLENS_OP_FLUSH = 2,
	IOLENS_OP_DISCARD = 3,
	IOLENS_OP_OTHER = 4,
};

struct inflight_req {
	__u64 insert_ns; /* 0 if request skipped the scheduler */
	__u64 issue_ns;
	__u64 cgid;
	__u32 bytes;
	__u8 op;
	__u8 _pad[3];
};

struct hist_key {
	__u64 cgid;
	__u32 dev; /* major << 20 | minor, same as kernel MKDEV */
	__u8 op;
	__u8 _pad[3];
};

struct hist {
	__u64 dev_slots[NUM_SLOTS];
	__u64 tot_slots[NUM_SLOTS];
	__u64 count;
	__u64 bytes;
	__u64 errors;
	__u64 queue_ns;
	__u64 dev_ns;
	__u64 tot_ns;
};

#endif
