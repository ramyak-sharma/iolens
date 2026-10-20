#!/bin/bash
# V1: latency accuracy against a device with known latency.
# null_blk with timer completions finishes every request after exactly
# completion_nsec, so p50 and p99 should both be that number.
# pass: within one bucket (25%) of configured value and of fios clat
source "$(dirname "$0")/lib.sh"
need_root
need fio python3 modprobe

out=$RAW/v1.json
echo '{"env":'"$(env_json)"',"runs":[' >"$out"
first=1
for ms in 1 5 20; do
	log "null_blk at ${ms}ms"
	dev=$(nullb_up irqmode=2 completion_nsec=$((ms * 1000000)))
	"$IOLENS" once --duration 32s --k8s off --devices nullb0 >"$RAW/v1-$ms-iolens.json" &
	pid=$!
	sleep 1
	fio --name=v1 --filename="$dev" --rw=randread --bs=4k --iodepth=1 --direct=1 \
		--runtime=30s --time_based --output-format=json >"$RAW/v1-$ms-fio.json"
	wait $pid
	nullb_down
	[ $first = 1 ] || echo , >>"$out"
	first=0
	python3 "$ROOT/scripts/analyze.py" v1 "$ms" "$RAW/v1-$ms-iolens.json" "$RAW/v1-$ms-fio.json" >>"$out"
done
echo ']}' >>"$out"
python3 "$ROOT/scripts/analyze.py" show-v1 "$out"
