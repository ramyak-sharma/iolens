#!/bin/bash
# make demo-down: delete the cluster, unmount the data disk
set -euo pipefail
CLUSTER=${CLUSTER:-iolens}
kind delete cluster --name "$CLUSTER"
if mountpoint -q /mnt/data 2>/dev/null; then
	sudo umount /mnt/data
fi
