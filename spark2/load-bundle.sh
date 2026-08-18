#!/usr/bin/env bash
# SPARKSOC — Spark 2 bundle loader.  sudo ./load-bundle.sh /media/usb/sparksoc
set -euo pipefail

SRC="${1:?usage: $0 /path/to/bundle}"
DEST="${SPARKSOC_ROOT:-/opt/sparksoc}"

RED=$'\033[31m'; GRN=$'\033[32m'; CYN=$'\033[36m'; RST=$'\033[0m'
log() { printf '%s[%s]%s %s\n' "$CYN" "$(date +%H:%M:%S)" "$RST" "$*"; }
ok()  { printf '%s  OK  %s %s\n' "$GRN" "$RST" "$*"; }
die() { printf '%s FAIL %s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

[[ -f "$SRC/MANIFEST.json" ]] || die "MANIFEST.json not found in $SRC"
command -v jq >/dev/null || die "jq is required"

log "verifying bundle integrity"
bash "$SRC/verify-bundle.sh" || die "bundle verification failed"

mkdir -p "$DEST"/{models,state,logs}

log "extracting code"
tar -xzf "$SRC/sparksoc-code.tar.gz" -C /tmp
rsync -a --delete /tmp/stage-code/ "$DEST/code/"

log "extracting gpt-oss-120b weights (~63 GB, be patient)"
if [[ -f "$SRC/sparksoc-models-spark2.tar" ]]; then
  tar -xf "$SRC/sparksoc-models-spark2.tar" -C /tmp
else
  tar -xzf "$SRC/sparksoc-models-spark2.tar.gz" -C /tmp
fi
rsync -a --info=progress2 /tmp/stage-models-spark2/ "$DEST/models/"
ok "models -> $DEST/models"
du -sh "$DEST/models"/*

log "loading vLLM image"
tar -xzf "$SRC/sparksoc-images.tar.gz" -C /tmp
docker load -i /tmp/images/vllm.tar

ref=$(jq -r '.images[] | select(.alias=="vllm") | .ref' "$SRC/MANIFEST.json")
arch=$(docker image inspect "$ref" --format '{{.Architecture}}')
[[ "$arch" == "arm64" ]] || die "image architecture is $arch, expected arm64"
ok "image $ref loaded (arm64)"

rm -rf /tmp/stage-code /tmp/stage-models-spark2 /tmp/images

cat <<MSG

${GRN}Spark 2 bundle loaded.${RST}

  cd $DEST/code/spark2
  cp .env.example .env && chmod 600 .env
  \$EDITOR .env            # VLLM_API_KEY must match Spark 1 and the harness
  docker compose up -d
  ./init.sh

MSG
