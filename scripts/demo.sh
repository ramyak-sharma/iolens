#!/bin/bash
# make demo-run: the noisy neighbour scenario, scripted.
#   0s    db starts (quiet random reads)
#   120s  noisy-writer starts (buffered sequential writes, full speed)
#   240s  noisy-writer deleted
#   270s  check and exit
# pass: noisy-neighbour fires within 10s of the writer starting, names
# noisy-writer as culprit and db as victim, and clears within 30s of it
# stopping. exits non zero otherwise. the expected numbers are a
# hypothesis, what actually happened goes into docs/raw/demo-runs.jsonl
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLUSTER=${CLUSTER:-iolens}
NODE=$CLUSTER-control-plane
NOISY_AT=${NOISY_AT:-120}
STOP_AT=${STOP_AT:-240}
END_AT=${END_AT:-270}
RAW=$ROOT/docs/raw
mkdir -p "$RAW"
log() { printf '\033[1m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

dev=$(docker exec "$NODE" cat /var/lib/iolens-disk.dev 2>/dev/null || basename "${DISK:-/dev/vdb}")
pod=$(kubectl -n iolens-system get pod -l app=iolens -o jsonpath='{.items[0].metadata.name}')
findings() { kubectl get --raw "/api/v1/namespaces/iolens-system/pods/$pod:9187/proxy/findings"; }
stamp=$(date -u +%Y%m%dT%H%M%SZ)

# noisy-neighbour finding naming db as victim, as "culprit sentence" or empty
nn() {
	findings | python3 -c '
import json, sys
d = json.load(sys.stdin)
for f in d["findings"] or []:
    if f["rule"] == "noisy-neighbour" and f["victim"] == "default/db":
        print(json.dumps(f)); break'
}

kubectl delete pod db noisy-writer --ignore-not-found --wait=true >/dev/null

# iostat beside it, to show what the standard tool alone would have said
docker rm -f iolens-iostat >/dev/null 2>&1 || true
docker run -d --rm --name iolens-iostat iolens-fio:dev iostat -x -t "$dev" 1 "$((END_AT + 5))" >/dev/null
trap 'docker logs iolens-iostat >"$RAW/demo-$stamp-iostat.txt" 2>&1 || true; docker rm -f iolens-iostat >/dev/null 2>&1 || true' EXIT

t0=$(date +%s)
el() { echo $(($(date +%s) - t0)); }
log "t=0 starting db on $dev"
kubectl apply -f "$ROOT/deploy/demo/db.yaml" >/dev/null
kubectl wait --for=condition=Ready pod/db --timeout=60s >/dev/null

early=""
while [ "$(el)" -lt "$NOISY_AT" ]; do
	f=$(nn || true)
	[ -n "$f" ] && early=$f
	sleep 2
done
[ -n "$early" ] && log "warning: finding before the noise started: $early"

log "t=$(el) starting noisy-writer"
kubectl apply -f "$ROOT/deploy/demo/noisy-writer.yaml" >/dev/null
# count from when the writer is actually running, not from kubectl apply
kubectl wait --for=condition=Ready pod/noisy-writer --timeout=60s >/dev/null
tn=$(date +%s)
fired="" fired_after=""
while [ "$(el)" -lt "$STOP_AT" ]; do
	if [ -z "$fired" ]; then
		f=$(nn || true)
		if [ -n "$f" ]; then
			fired=$f
			fired_after=$(($(date +%s) - tn))
			log "t=$(el) fired after ${fired_after}s: $(echo "$f" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sentence"])')"
		fi
	fi
	sleep 1
done

log "t=$(el) deleting noisy-writer"
kubectl delete pod noisy-writer --grace-period=0 --wait=false >/dev/null
ts=$(date +%s)
cleared_after=""
# keep looking a bit past END_AT so a slow clear is measured, not just failed
while [ $(($(date +%s) - ts)) -lt $((END_AT - STOP_AT + 30)) ]; do
	if [ -n "$fired" ] && [ -z "$(nn || true)" ]; then
		cleared_after=$(($(date +%s) - ts))
		log "t=$(el) cleared after ${cleared_after}s"
		break
	fi
	sleep 1
done
kubectl delete pod db --wait=false >/dev/null

result=$(FIRED="$fired" FA="$fired_after" CA="$cleared_after" EARLY="$early" DEV="$dev" STAMP="$stamp" python3 -c '
import json, os
f = json.loads(os.environ["FIRED"]) if os.environ["FIRED"] else None
fa = int(os.environ["FA"]) if os.environ["FA"] else None
ca = int(os.environ["CA"]) if os.environ["CA"] else None
ok = (f is not None and fa <= 10 and f["culprit"] == "default/noisy-writer"
      and f["victim"] == "default/db" and ca is not None and ca <= 30 and not os.environ["EARLY"])
print(json.dumps({"run": os.environ["STAMP"], "device": os.environ["DEV"], "fired_after_s": fa,
    "cleared_after_s": ca, "finding": f, "false_positive_before_noise": bool(os.environ["EARLY"]), "pass": ok}))')
echo "$result" >>"$RAW/demo-runs.jsonl"
echo "$result" | python3 -m json.tool
echo "$result" | grep -q '"pass": true'
