#!/bin/bash
# make demo-up: data disk, single node kind cluster, iolens + prometheus +
# grafana, then wait until the rules finished warming up.
#
#   DISK=/dev/vdb (default)  formats it! ext4, mounted at /mnt/data
#   DISK=loop                no spare disk, use a loop device inside the kind
#                            node instead (docker desktop, CI, etc)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DISK=${DISK:-/dev/vdb}
CLUSTER=${CLUSTER:-iolens}
NODE=$CLUSTER-control-plane
log() { printf '\033[1m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

for c in docker kind kubectl; do command -v $c >/dev/null || { log "missing $c"; exit 1; }; done

kcfg=$(mktemp)
if [ "$DISK" != loop ]; then
	if ! mountpoint -q /mnt/data; then
		if [ "${FORCE:-}" != 1 ]; then
			read -rp "format $DISK as ext4? everything on it is lost [y/N] " ok
			[ "$ok" = y ] || exit 1
		fi
		sudo mkfs.ext4 -F -q "$DISK"
		sudo mkdir -p /mnt/data
		sudo mount "$DISK" /mnt/data
	fi
	# so scheduler queueing is visible as well as device queueing
	echo mq-deadline | sudo tee /sys/block/"$(basename "$DISK")"/queue/scheduler >/dev/null
	cat >"$kcfg" <<YAML
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: /mnt/data
        containerPath: /mnt/data
YAML
else
	printf 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n' >"$kcfg"
fi

if ! kind get clusters | grep -qx "$CLUSTER"; then
	log "creating kind cluster $CLUSTER"
	kind create cluster --name "$CLUSTER" --config "$kcfg" --wait 120s
fi
rm -f "$kcfg"

if [ "$DISK" = loop ]; then
	log "loop data disk inside $NODE"
	docker exec "$NODE" bash -c '
		set -e
		if ! mountpoint -q /mnt/data; then
			truncate -s 8G /var/lib/iolens-disk.img
			dev=$(losetup --direct-io=on -f --show /var/lib/iolens-disk.img)
			mkfs.ext4 -q "$dev"
			mkdir -p /mnt/data && mount "$dev" /mnt/data
			echo mq-deadline > /sys/block/$(basename $dev)/queue/scheduler 2>/dev/null || true
			basename "$dev" > /var/lib/iolens-disk.dev
		fi'
fi

log "writing 1G db file so reads hit the disk"
docker exec "$NODE" bash -c 'mkdir -p /mnt/data/db /mnt/data/noisy
	[ -s /mnt/data/db/file ] || dd if=/dev/urandom of=/mnt/data/db/file bs=1M count=1024 oflag=direct status=none'

log "building images"
docker build -q -t iolens:dev "$ROOT" >/dev/null
docker build -q -t iolens-fio:dev -f "$ROOT/deploy/demo/fio.Dockerfile" "$ROOT/deploy/demo" >/dev/null
kind load docker-image iolens:dev iolens-fio:dev --name "$CLUSTER"

log "applying manifests"
kubectl apply -f "$ROOT/deploy/"
kubectl apply -f "$ROOT/deploy/observability/prometheus.yaml" -f "$ROOT/deploy/observability/grafana.yaml"
kubectl -n iolens-system create configmap grafana-dashboards \
	--from-file="$ROOT/deploy/observability/iolens-dashboard.json" \
	--dry-run=client -o yaml | kubectl apply -f -
kubectl -n iolens-system rollout restart ds/iolens >/dev/null
kubectl -n iolens-system rollout status ds/iolens --timeout=120s
kubectl -n iolens-system rollout status deploy/prometheus deploy/grafana --timeout=180s

pod=$(kubectl -n iolens-system get pod -l app=iolens -o jsonpath='{.items[0].metadata.name}')
log "waiting for rules to warm up (about 2 minutes)"
until kubectl get --raw "/api/v1/namespaces/iolens-system/pods/$pod:9187/proxy/findings" 2>/dev/null | grep -q '"warming":false'; do
	sleep 5
done
log "ready. grafana: kubectl -n iolens-system port-forward svc/grafana 3000"
