#!/bin/bash
# V2: device statistics against iostat. mixed fio job on a file on the
# data disk (not the raw device, that would wreck the filesystem), iostat
# and iolens watching the same 60 1s windows.
# pass: r/s w/s kB/s within 2%, await within 5%
source "$(dirname "$0")/lib.sh"
need_root
need fio iostat python3

DEV=${DEV:-vdb}
TARGET=${TARGET:-/mnt/data/v2.fio}
SECS=${SECS:-60}

log "fio 70/30 randrw on $TARGET, comparing on $DEV for ${SECS}s"
fio --name=prep --filename="$TARGET" --size=2G --rw=write --bs=1M --direct=1 >/dev/null

fio --name=v2 --filename="$TARGET" --size=2G --rw=randrw --rwmixread=70 \
	--bssplit=4k/50:64k/50 --iodepth=16 --ioengine=libaio --direct=1 \
	--runtime="$((SECS + 6))s" --time_based >/dev/null &
pf=$!
sleep 2

# both tools take their first sample on the same whole second, otherwise
# the 1s windows are out of phase and a bursty load makes them disagree
"$IOLENS" once --align --duration "$((SECS + 1))s" --k8s off --devices "$DEV" >"$RAW/v2-iolens.json" &
p1=$!
python3 -c 'import time; time.sleep(1 - time.time() % 1)'
S_TIME_FORMAT=ISO iostat -x -y -o JSON -t "$DEV" 1 "$SECS" >"$RAW/v2-iostat.json" &
p2=$!
wait $p1 $p2 $pf
rm -f "$TARGET"

echo '{"env":'"$(env_json)"',"result":' >"$RAW/v2.json"
python3 "$ROOT/scripts/analyze.py" v2 "$DEV" "$RAW/v2-iolens.json" "$RAW/v2-iostat.json" >>"$RAW/v2.json"
echo '}' >>"$RAW/v2.json"
python3 "$ROOT/scripts/analyze.py" show-v2 "$RAW/v2.json"
