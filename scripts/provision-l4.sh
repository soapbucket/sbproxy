#!/usr/bin/env bash
# Provision (or tear down) a single NVIDIA L4 GPU VM on GCP for the
# model-host certification (WOR-1652). Single-node, one cloud GPU; no
# cluster, no autoscaling. Costs money while it runs, so `down` when
# done.
#
# Prereqs: `gcloud auth login` done, and L4 quota (NVIDIA_L4_GPUS) in
# the target region. Check quota first with:
#   gcloud compute regions describe "$REGION" \
#     --format="value(quotas)" | tr ',' '\n' | grep -i l4
#
# Usage:
#   scripts/provision-l4.sh up      # create the VM
#   scripts/provision-l4.sh ssh     # ssh in
#   scripts/provision-l4.sh down    # delete the VM (stops billing)
set -euo pipefail

PROJECT="${SBPROXY_GCP_PROJECT:-sbproxy-bench-2026}"
ZONE="${SBPROXY_GCP_ZONE:-us-central1-a}"
VM="${SBPROXY_GCP_VM:-sbproxy-modelhost-l4}"
# g2 is the L4 machine family. g2-standard-8 = 8 vCPU / 32 GB / 1x L4 24GB.
MACHINE="${SBPROXY_GCP_MACHINE:-g2-standard-8}"
# Deep Learning VM image: CUDA driver preinstalled, so no driver dance.
IMAGE_FAMILY="${SBPROXY_GCP_IMAGE_FAMILY:-common-cu124-ubuntu-2204}"
IMAGE_PROJECT="deeplearning-platform-release"
BOOT_DISK_GB="${SBPROXY_GCP_DISK_GB:-200}"

case "${1:-}" in
  up)
    echo "Creating $VM ($MACHINE, 1x L4) in $ZONE of $PROJECT ..."
    gcloud compute instances create "$VM" \
      --project="$PROJECT" \
      --zone="$ZONE" \
      --machine-type="$MACHINE" \
      --accelerator="type=nvidia-l4,count=1" \
      --maintenance-policy=TERMINATE \
      --image-family="$IMAGE_FAMILY" \
      --image-project="$IMAGE_PROJECT" \
      --boot-disk-size="${BOOT_DISK_GB}GB" \
      --boot-disk-type=pd-ssd \
      --metadata="install-nvidia-driver=True" \
      --scopes=cloud-platform
    echo "Done. SSH with: $0 ssh"
    ;;
  ssh)
    gcloud compute ssh "$VM" --project="$PROJECT" --zone="$ZONE"
    ;;
  down)
    echo "Deleting $VM (this stops billing) ..."
    gcloud compute instances delete "$VM" --project="$PROJECT" --zone="$ZONE" --quiet
    ;;
  *)
    echo "usage: $0 {up|ssh|down}" >&2
    exit 2
    ;;
esac
