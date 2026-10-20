# shared bits for the validation scripts. source it, dont run it
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IOLENS=${IOLENS:-$ROOT/bin/iolens}
RAW=${RAW:-$ROOT/docs/raw}
mkdir -p "$RAW"

log() { printf '\033[1m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "error: $*"; exit 1; }

need_root() { [ "$(id -u)" = 0 ] || die "run as root (sudo)"; }

need() {
	for c in "$@"; do
		command -v "$c" >/dev/null || die "missing $c"
	done
}

# null_blk with given module args, prints the device path
nullb_up() {
	modprobe -r null_blk 2>/dev/null || true
	modprobe null_blk nr_devices=1 queue_mode=2 "$@" ||
		die "null_blk not available, install linux-modules-extra-\$(uname -r)"
	udevadm settle 2>/dev/null || sleep 1
	echo /dev/nullb0
}

nullb_down() { modprobe -r null_blk 2>/dev/null || true; }

# environment line for results, so numbers are never quoted without it
env_json() {
	python3 - <<PY
import json, os, platform
print(json.dumps({
  "kernel": platform.release(),
  "arch": platform.machine(),
  "cpus": os.cpu_count(),
  "mem_gib": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1),
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
}))
PY
}
