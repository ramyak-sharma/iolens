# iolens

Per-pod block I/O latency for Linux nodes, measured in the kernel with eBPF.

`iostat` tells you a disk's average await. When p99 latency goes up on a node, the questions on-call actually has are which workload did it, and whether the disk got slow or is just busy. Averages per device can answer neither, so iolens measures every block request, splits its latency into queue time and device time, charges it to the cgroup (and so the Kubernetes pod) that caused it, and says what it sees in plain sentences.

```
noisy-neighbour  vda: default/db read p99 rose 2.9ms -> 53.3ms (18x)
                 while default/noisy-writer went to 99% of device bytes
```

That finding is from a real `make demo` run, 5 seconds after the noisy pod started. Measured numbers for everything are in [docs/results.md](docs/results.md).

## How it works

```
 kernel                                     user space (once a second)
 ------                                     --------------------------
 block_rq_insert  --+                       iolens agent
 block_rq_issue   --+--> inflight map  --+    read hists (batch lookup)
 block_rq_complete -+    (LRU, per req)  |    /proc/diskstats, PSI, io.stat
                                         |    cgroup id -> path -> pod
                         hists map  <----+    build one Snapshot, atomic swap
                         (cgroup, dev, op)        |
                         log-linear buckets       +--> Prometheus :9187/metrics
                                                  +--> rules -> findings
                                                  +--> iolens top
```

**Kernel side** (`bpf/iolens.bpf.c`, about 200 lines). Three `tp_btf` programs on the block tracepoints. Insert and issue record timestamps in an in-flight map keyed by the `struct request` pointer. Completion computes device time (complete minus issue) and total time (complete minus insert), then adds one to a bucket in a histogram keyed by (cgroup, device, op). Nothing is copied to user space per request. CO-RE means one compiled object runs on any 6.1+ kernel with BTF.

**Which cgroup.** Completion runs in interrupt context, and buffered writes are issued by kernel writeback threads, so "the current task" is the wrong answer both times. iolens reads `rq->bio->bi_blkg->blkcg`, which is the cgroup the kernel's own I/O controller charges. V3 checks this with buffered writes: they land on the writer's cgroup, byte for byte, not on the flusher thread.

**Histograms.** Each power of two in microseconds is split into 4 linear sub-buckets, so a bucket is at most 25% wide (plain log2 buckets would be 100%). 100 buckets cover 0 to about 33 s. The same bucket function exists in C and Go and a table test keeps them in sync. Counters are cumulative and never reset in the kernel; user space subtracts snapshots.

**User space** (Go, [cilium/ebpf](https://github.com/cilium/ebpf), no cgo). One collector goroutine ticks every second and publishes an immutable snapshot. Prometheus, the rules and the TUI only read snapshots, so a scrape storm cannot slow down the BPF reads.

**Rules.** Six simple rules with baselines (EWMA, 2.5 minute half-life), a 2 minute warm-up and hysteresis (3 evaluations to fire, 6 to clear). Baselines freeze while a finding about them is active, so a long incident does not become the new normal.

| rule | fires when |
| --- | --- |
| noisy-neighbour | a pod's p99 is 3x its baseline while another pod has at least half the device's bytes or IOs and 3x its usual throughput |
| device-slow | device time p99 is 3x baseline with queue depth under 1 and no extra load |
| saturated | queue depth at least 8 and node PSI some at least 10% |
| queueing-dominant | a pod's mean queue time is bigger than its mean device time |
| io-stall | PSI full at least 5%, node or pod |
| io-errors | any completion with an error |

Thresholds can be changed with `--config rules.yaml`.

## Results

From [docs/results.md](docs/results.md), which `scripts/results.sh` generates from the raw script output. Misses stay in.

| criterion | target | result |
| --- | --- | --- |
| Latency accuracy | within 25% | not run |
| Device-stat parity | 2% rates, 5% await | pass (median) |
| Attribution | within 1% | pass |
| Overhead | at most 5% IOPS loss | 11.9% (missed, loop-on-tmpfs) |
| Per-event cost | reported | issue 255 ns, complete 221 ns |
| Agent footprint | under 100 MB RSS, under 2% of a core | 42 MiB, 0.05% (under load, not idle) |
| Detection | 5 of 5 within 10 s | 5 of 5 |

All of these so far ran on Docker Desktop's Linux VM (kernel 6.10, arm64), not the Lima VM the spec targets. It has no `null_blk`, so V1 has not run yet and V4 used a loop device on tmpfs instead. Both need a rerun in Lima.

What `iostat -x 1` showed for the same demo run, before and after the writer started:

```
Device   r/s   r_await   w/s     wkB/s   w_await  aqu-sz  %util
loop0    200   0.58      0       0       0.00     0.12    15.2
loop0    185   7.50      1010    721028  15.07    17.06   89.8
```

A busy disk and a higher average await, but no way to tell who is suffering or who caused it. iolens named both within 5 seconds.

## Running it

Needs Linux 6.1+ with BTF (`/sys/kernel/btf/vmlinux`), cgroup v2, and root. On macOS, everything runs in a Lima VM:

```sh
limactl disk create data --size 20GiB
limactl start --name=iolens ./lima.yaml
limactl shell iolens
cd ~/iolens
make build
sudo ./bin/iolens top          # terminal view
sudo ./bin/iolens serve        # metrics on :9187, findings on /findings
sudo ./bin/iolens once --duration 10s   # json summary
```

`--no-bpf` runs without eBPF (diskstats, PSI and io.stat per cgroup only) for kernels without BTF.

### The demo

```sh
make demo          # formats /dev/vdb! single node kind cluster, then the scenario
DISK=loop make demo   # no spare disk: loop device inside the kind node
make demo-down
```

`make demo` starts a rate-limited reader pod (`db`), then 2 minutes later a pod doing full speed buffered writes (`noisy-writer`), deletes it 2 minutes after that, and fails unless the noisy-neighbour finding fired within 10 s naming the right pods and cleared within 30 s. Grafana: `kubectl -n iolens-system port-forward svc/grafana 3000`.

### Make targets

| target | does |
| --- | --- |
| `make generate` | recompile the BPF program and regenerate `internal/bpfsrc` (needs clang, libbpf-dev) |
| `make build` | static binary in `bin/iolens` (generated code is committed, so no clang needed) |
| `make test` | unit tests, vet, staticcheck |
| `make itest` | load and attach on the running kernel, as root |
| `make image` | multi-arch container image |
| `make validate` | V1 to V4, then writes `docs/results.md` |

### Privileges

The minimum is `CAP_BPF`, `CAP_PERFMON` and (only on kernels that still charge BPF memory to memlock) `CAP_SYS_RESOURCE`, with a read-only root filesystem and read-only mounts of `/sys/fs/cgroup` and `/sys/kernel/btf`. The DaemonSet in `deploy/` uses `privileged: true` because kind's nested containers make capability-only setups fiddly. RBAC is get, list and watch on pods, nothing else.

## Limitations

- Time spent waiting for a free request tag happens before a `struct request` exists, so the tracepoints cannot time it. PSI does count it, and the saturated and io-stall rules use PSI.
- Bio-based devices (device-mapper, md RAID) are not seen as themselves. Their I/O shows up on the physical devices underneath, still attributed by cgroup. Loop devices pass the original cgroup down too, which is why the demo's finding is on `vda`, the disk under the loop device.
- Journal and metadata writes (jbd2) are charged to the root cgroup, so part of a pod's real cost shows as root.
- Percentiles come from buckets: at most 25% error inside the agent, and up to 2x in Grafana's `histogram_quantile`, since Prometheus only gets the power of two boundaries.
- Shared atomic counters bounce cache lines when many CPUs complete I/O for the same key. On a near zero latency device this costs real IOPS (see V4). A per-CPU variant is the next step.
- Tested on a single node. Multi-node should work since everything is per node, but it is not verified.

## Layout

```
bpf/                  eBPF program, shared header, vmlinux.h
cmd/iolens/           serve, top, once
internal/bpfsrc/      bpf2go output (committed)
internal/probe/       load, attach, read maps
internal/hist/        buckets, percentiles
internal/diskstats/   /proc/diskstats
internal/psi/         pressure files
internal/cgroupmap/   cgroup id -> path -> pod, io.stat
internal/k8s/         node scoped pod informer
internal/collector/   snapshots
internal/rules/       diagnosis rules
internal/export/      Prometheus
internal/tui/         iolens top
deploy/               DaemonSet, RBAC, Prometheus, Grafana, demo pods
scripts/              validation (V1 to V4), demo, results
```
