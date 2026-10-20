#!/bin/bash
# V4: overhead. worst case for a per request tracer is a device that
# completes instantly, since then the tracers fixed cost is the biggest
# share of each request. null_blk irqmode=0 completes in the submit path.
# 5 runs without iolens, 5 with. whatever the number is, it gets published
#
# NULLB=0 uses a loop device on tmpfs instead, for machines without
# null_blk. slower than null_blk so overhead looks smaller, results say so
source "$(dirname "$0")/lib.sh"
need_root
need fio python3

RUNS=${RUNS:-5}
SECS=${SECS:-30}
NULLB=${NULLB:-1}

if [ "$NULLB" = 1 ]; then
	dev=$(nullb_up irqmode=0)
	kind=null_blk
else
	mkdir -p /dev/shm/iolens-v4
	truncate -s 2G /dev/shm/iolens-v4/img
	dev=$(losetup --direct-io=off -f --show /dev/shm/iolens-v4/img)
	kind=loop-on-tmpfs
fi
name=$(basename "$dev")
cleanup() {
	[ -n "${agent:-}" ] && kill "$agent" 2>/dev/null || true
	if [ "$NULLB" = 1 ]; then nullb_down; else losetup -d "$dev"; rm -rf /dev/shm/iolens-v4; fi
}
trap cleanup EXIT

run_fio() {
	fio --name=v4 --filename="$dev" --rw=randread --bs=4k --iodepth=32 --numjobs=4 \
		--ioengine=libaio --direct=1 --runtime="${SECS}s" --time_based --group_reporting \
		--output-format=json | python3 -c 'import json,sys; print(json.load(sys.stdin)["jobs"][0]["read"]["iops"])'
}

log "device $dev ($kind), $RUNS runs of ${SECS}s each way"
off=()
for i in $(seq "$RUNS"); do off+=("$(run_fio)"); log "off run $i: ${off[-1]} iops"; done

"$IOLENS" serve --k8s off --listen 127.0.0.1:9188 --log-file "$RAW/v4-agent.log" &
agent=$!
sleep 3
t0=$(awk '{print $14+$15}' /proc/$agent/stat)
s0=$(date +%s.%N)
on=()
for i in $(seq "$RUNS"); do on+=("$(run_fio)"); log "on run $i: ${on[-1]} iops"; done
t1=$(awk '{print $14+$15}' /proc/$agent/stat)
s1=$(date +%s.%N)
rss_kb=$(awk '/VmRSS/{print $2}' /proc/$agent/status)
curl -s 127.0.0.1:9188/metrics | grep '^iolens_agent_bpf_run_ns_per_event' >"$RAW/v4-bpfstats.txt" || true
kill $agent
wait $agent 2>/dev/null || true
agent=

hz=$(getconf CLK_TCK)
python3 "$ROOT/scripts/analyze.py" v4 "$kind" "$(env_json)" "${off[*]}" "${on[*]}" \
	"$(python3 -c "print(($t1-$t0)/$hz/($s1-$s0))")" "$rss_kb" "$RAW/v4-bpfstats.txt" >"$RAW/v4.json"
python3 "$ROOT/scripts/analyze.py" show-v4 "$RAW/v4.json"
