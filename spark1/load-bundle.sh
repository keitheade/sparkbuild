#!/usr/bin/env bash
# =============================================================================
# SPARKSOC — Spark 1 bundle loader. Run once, from the USB mount point.
#   sudo ./load-bundle.sh /media/usb/sparksoc
# =============================================================================
set -euo pipefail

SRC="${1:?usage: $0 /path/to/bundle}"
DEST="${SPARKSOC_ROOT:-/opt/sparksoc}"

RED=$'\033[31m'; GRN=$'\033[32m'; CYN=$'\033[36m'; RST=$'\033[0m'
log() { printf '%s[%s]%s %s\n' "$CYN" "$(date +%H:%M:%S)" "$RST" "$*"; }
ok()  { printf '%s  OK  %s %s\n' "$GRN" "$RST" "$*"; }
die() { printf '%s FAIL %s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

[[ -f "$SRC/MANIFEST.json" ]] || die "MANIFEST.json not found in $SRC"
command -v jq >/dev/null || die "jq is required"
command -v docker >/dev/null || die "docker is required"

log "verifying bundle integrity"
bash "$SRC/verify-bundle.sh" || die "bundle verification failed — do not proceed"

mkdir -p "$DEST"/{models,attack,wheelhouse,state,logs}

log "extracting code"
tar -xzf "$SRC/sparksoc-code.tar.gz" -C /tmp
rsync -a --delete /tmp/stage-code/ "$DEST/code/"
ok "code -> $DEST/code"

log "extracting ATT&CK data"
tar -xzf "$SRC/sparksoc-attack.tar.gz" -C /tmp
cp -f /tmp/attack/*.json "$DEST/attack/"
ok "attack -> $DEST/attack"

log "extracting wheelhouse"
tar -xzf "$SRC/sparksoc-wheelhouse.tar.gz" -C /tmp
rsync -a /tmp/wheelhouse/ "$DEST/wheelhouse/"
ok "wheelhouse -> $DEST/wheelhouse ($(ls -1 "$DEST/wheelhouse"/*.whl | wc -l) wheels)"

log "extracting model weights for spark1 (this takes a while)"
if [[ -f "$SRC/sparksoc-models-spark1.tar" ]]; then
  tar -xf "$SRC/sparksoc-models-spark1.tar" -C /tmp
else
  tar -xzf "$SRC/sparksoc-models-spark1.tar.gz" -C /tmp
fi
rsync -a /tmp/stage-models-spark1/ "$DEST/models/"
ok "models -> $DEST/models"
du -sh "$DEST/models"/* 2>/dev/null || true

log "loading container images"
tar -xzf "$SRC/sparksoc-images.tar.gz" -C /tmp
for tar in /tmp/images/*.tar; do
  log "  docker load < $(basename "$tar")"
  docker load -i "$tar"
done

log "verifying image architecture and digests"
fail=0
while read -r alias ref digest; do
  arch=$(docker image inspect "$ref" --format '{{.Architecture}}' 2>/dev/null || echo MISSING)
  if [[ "$arch" != "arm64" ]]; then
    printf 'ARCH FAIL %-10s %s -> %s\n' "$alias" "$ref" "$arch"; fail=1
  else
    printf '  ok      %-10s %s (arm64)\n' "$alias" "$ref"
  fi
done < <(jq -r '.images[] | "\(.alias) \(.ref) \(.digest // "none")"' "$SRC/MANIFEST.json")
[[ $fail -eq 0 ]] || die "one or more images are not arm64 — re-stage with the containerd image store enabled"

log "creating python venv for the ingestion tooling"
python3 -m venv "$DEST/code/spark1/venv"
"$DEST/code/spark1/venv/bin/pip" install --no-index --find-links "$DEST/wheelhouse" \
    -r "$DEST/code/spark1/requirements.txt"
ok "venv ready (offline install from wheelhouse)"

rm -rf /tmp/stage-code /tmp/attack /tmp/wheelhouse /tmp/stage-models-spark1 /tmp/images

cat <<MSG

${GRN}Spark 1 bundle loaded.${RST}

  cd $DEST/code/spark1
  cp .env.example .env && chmod 600 .env
  \$EDITOR .env                 # set VLLM_API_KEY, QDRANT_API_KEY, MODEL_ROOT
  docker compose up -d
  ./init.sh

MSG
