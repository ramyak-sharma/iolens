#!/bin/bash
# V3: attribution. two fio jobs at once in two cgroups, each writing a known
# amount. first with O_DIRECT, then buffered, which is the interesting one:
# writeback is done by kernel flusher threads, so a tool that charges the
# current task would blame them instead of the writer.
# pass: each cgroups bytes in iolens within 1% of what fio wrote, and
# agree with the cgroups own io.stat
#
# uses plain cgroup dirs instead of systemd-run --scope so it also works
# in containers without systemd, same thing as far as the kernel cares
source "$(dirname "$0")/lib.sh"
need_root
need fio python3

DEV=${DEV:-vdb}
DIR=${DIR:-/mnt/data}
CG=/sys/fs/cgroup/iolens-v3

cleanup() {
	for c in a b; do
		[ -d $CG/$c ] && cat $CG/$c/cgroup.procs 2>/dev/null | xargs -r kill 2>/dev/null || true
		rmdir $CG/$c 2>/dev/null || true
	done
	rmdir $CG 2>/dev/null || true
	rm -f "$DIR"/v3-a "$DIR"/v3-b
}
trap cleanup EXIT

grep -qw io /sys/fs/cgroup/cgroup.subtree_control || echo +io >/sys/fs/cgroup/cgroup.subtree_control
mkdir -p $CG
echo +io >$CG/cgroup.subtree_control

echo '{"env":'"$(env_json)"',"runs":[' >"$RAW/v3.json"
first=1
for mode in direct buffered; do
	mkdir -p $CG/a $CG/b
	direct=1
	[ $mode = buffered ] && direct=0
	log "two writers, $mode"
	"$IOLENS" once --duration 25s --k8s off --devices "$DEV" >"$RAW/v3-$mode-iolens.json" &
	pid=$!
	sleep 2
	# 512M and 256M, different on purpose so a swap would show
	bash -c "echo \$\$ >$CG/a/cgroup.procs; exec fio --name=a --filename=$DIR/v3-a --size=512M --bs=1M --rw=write --direct=$direct --end_fsync=1 --output-format=json" >"$RAW/v3-$mode-fio-a.json" &
	pa=$!
	bash -c "echo \$\$ >$CG/b/cgroup.procs; exec fio --name=b --filename=$DIR/v3-b --size=256M --bs=1M --rw=write --direct=$direct --end_fsync=1 --output-format=json" >"$RAW/v3-$mode-fio-b.json" &
	pb=$!
	wait $pa $pb
	cp $CG/a/io.stat "$RAW/v3-$mode-iostat-a.txt"
	cp $CG/b/io.stat "$RAW/v3-$mode-iostat-b.txt"
	wait $pid || true
	[ $first = 1 ] || echo , >>"$RAW/v3.json"
	first=0
	python3 "$ROOT/scripts/analyze.py" v3 "$mode" "$DEV" "$RAW" >>"$RAW/v3.json"
	rmdir $CG/a $CG/b
	rm -f "$DIR"/v3-a "$DIR"/v3-b
done
echo ']}' >>"$RAW/v3.json"
python3 "$ROOT/scripts/analyze.py" show-v3 "$RAW/v3.json"
