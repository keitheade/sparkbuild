# 01 — Staging (Windows 11 x86_64 host)

Build the complete transfer bundle: model weights, linux/arm64 container images,
MITRE ATT&CK STIX data, an aarch64 Python wheelhouse, and the deployment code.

**Budget:** 4–8 hours wall clock, ~400 GB working disk, ~145 GB on USB.

---

## 1. Prerequisites

| Requirement | Check | Install |
|---|---|---|
| PowerShell 7+ | `$PSVersionTable.PSVersion` | `winget install Microsoft.PowerShell` |
| Docker Desktop, running | `docker info` | winget install Docker.DockerDesktop |
| **containerd image store enabled** | Settings → General | see §3 — this one bites |
| qemu binfmt for arm64 | `docker run --rm --platform linux/arm64 alpine uname -m` → `aarch64` | `docker run --privileged --rm tonistiigi/binfmt --install arm64` |
| Hugging Face CLI ≥ 0.34 | `hf --version` | `pip install -U "huggingface_hub[cli,hf_transfer]"` |
| tar | `tar --version` | built into Windows 10 1803+ |
| OpenSSH client | `ssh -V` | Settings → Optional Features |
| ~400 GB free on `WorkRoot` | | |
| USB formatted **exFAT or NTFS** | | FAT32 cannot hold >4 GB files |

```powershell
$env:HF_TOKEN = "hf_..."          # or: hf auth login
$env:HF_HUB_ENABLE_HF_TRANSFER = "1"
```

---

## 2. Configure

Edit `staging/config/staging.psd1`. The pins that matter:

```powershell
WorkRoot = 'D:\sparksoc-staging'
UsbRoot  = 'E:\sparksoc'

Attack = @{ Version = 'v17.1'; Url = 'https://raw.githubusercontent.com/.../enterprise-attack-17.1.json' }

SmokeGate = @{
    Enabled   = $true
    SparkHost = 'spark1.staging.local'   # a Spark still on the network
    SparkUser = 'nvidia'
    SshKey    = '~\.ssh\id_ed25519_spark'
}
```

Check the ATT&CK URL against <https://github.com/mitre-attack/attack-stix-data>
before running — the pinned filename changes with each release, and a 404
downloads an HTML error page that the script will reject as too small.

---

## 3. The containerd image store

You are pulling `linux/arm64` images on an `x86_64` host. Docker Desktop's
**legacy** image store can silently store the host-architecture image instead,
and `docker save` then produces a tar that fails with `exec format error` on the
Spark — after you have already carried it into the enclave.

**Docker Desktop → Settings → General → "Use containerd for pulling and storing images"**, then restart Docker.

`Images.ps1` asserts the architecture after every pull and throws if it is wrong,
so you cannot get past this stage with a bad image. But turn the setting on
first and save yourself the round trip.

---

## 4. Run

```powershell
cd C:\path\to\soc-airgap-spark\staging
.\Stage-SOCBundle.ps1
```

Stages are individually resumable:

```powershell
.\Stage-SOCBundle.ps1 -Stage Models              # just re-pull weights
.\Stage-SOCBundle.ps1 -Stage Images -Force       # re-pull and re-save images
.\Stage-SOCBundle.ps1 -Stage Smoke               # re-run the hardware gate only
.\Stage-SOCBundle.ps1 -Stage Bundle
```

| Stage | Does | Typical time |
|---|---|---|
| Preflight | prerequisites, disk, USB filesystem | seconds |
| Models | `hf download` × 3, validates shard indexes | 2–5 h |
| Images | arm64 pull + digest pin + arch assert + save | 20–40 min |
| Attack | STIX download, parse, object-count validation | 2 min |
| Wheelhouse | `pip wheel` inside an arm64 container under qemu | 10–25 min |
| **Smoke** | **hardware validation gate — see §5** | 30–60 min |
| Bundle | tar, split at 3.8 GB, SHA-256, verify script | 30–60 min |

Everything is logged to `<WorkRoot>\logs\staging-*.log`, and progress is
checkpointed into `MANIFEST.json` after each stage.

---

## 5. The smoke gate

This is the most important stage and the reason this build is likely to work.

You chose `vllm/vllm-openai:cu130-nightly` for provenance. The trade-off is that
official vLLM builds are **not guaranteed to carry sm_121 aarch64 kernels**
(vLLM issue #36821), and a nightly tag moves. If the image cannot serve on GB10,
you want to learn that here, on a machine with a network connection, not in the
enclave with a USB stick and no way to pull a fix.

`Test-SparkSmoke.ps1` copies the image and the smallest model to a Spark that is
still reachable, starts vLLM, and asserts:

| Test | What it proves |
|---|---|
| T0 | remote host is aarch64 |
| T1 | the saved image really is arm64 on the target |
| T2 | CUDA device visible, compute capability 12.1 |
| T3 | vLLM starts and `/health` responds |
| T4 | **a completion returns non-empty content** |
| T5 | a longer completion is coherent and terminates cleanly |
| T6 | `/v1/embeddings` returns a vector of nonzero dimension |

**T4 is the one that matters.** vLLM issue #37030 describes a shared-memory race
in the Marlin MoE 256-thread kernel on SM121 that returns HTTP 200 with a null
first Harmony token. `/health` passes. `/v1/models` passes. The model produces
nothing. Every naive check says the deployment is fine.

T4 only runs if a generative model is present on the smoke host. Copying 65 GB
over 1 GbE takes about 15 minutes; do it, because gpt-oss-120b at TP=1 is
exactly the configuration the bug affects:

```powershell
# On the staging host, before running the Smoke stage:
scp -r D:\sparksoc-staging\models\gpt-oss-120b nvidia@spark1.staging.local:/tmp/sparksoc-smoke/gen-model
```

If you have no Spark reachable at staging time, set `SmokeGate.Enabled = $false`
and read §7 before you carry the media across.

---

## 6. Transfer

```powershell
robocopy "D:\sparksoc-staging\bundle" "E:\sparksoc" /E /J /R:2 /W:5 /NP
```

`/J` uses unbuffered I/O, which is materially faster for multi-GB files.

Contents:

```
E:\sparksoc\
  MANIFEST.json                          machine-readable, SHA-256 of everything
  MANIFEST.txt                           human-readable summary
  verify-bundle.sh                       run this FIRST on each target
  sparksoc-code.tar.gz                   ~2 MB
  sparksoc-images.tar.gz                 ~12 GB   (split into parts)
  sparksoc-attack.tar.gz                 ~15 MB
  sparksoc-wheelhouse.tar.gz             ~120 MB
  sparksoc-models-spark1.tar             ~72 GB   (split into parts)
  sparksoc-models-spark2.tar             ~65 GB   (split into parts)
```

Model bundles are uncompressed `.tar` on purpose: safetensors are dense binary,
gzip returns 1–2% for 30+ minutes of CPU. Use `-CompressModels` to override.

Before ejecting, verify the media on the staging host:

```powershell
Get-ChildItem E:\sparksoc -Recurse -File |
  Measure-Object -Property Length -Sum |
  Select-Object Count, @{n='GB';e={[math]::Round($_.Sum/1GB,1)}}
```

Also stage `jq` for aarch64 — `verify-bundle.sh` needs it and the Sparks may not
have it. If your Spark image lacks it, add the `.deb` to the USB manually.

---

## 7. Fallback: the image cannot serve on GB10

If the smoke gate fails T3 with `no kernel image is available for execution` or
similar, the official image lacks sm_121 aarch64 kernels. You have three options,
in order of preference.

### Option A — build a pinned sm_121a image on a Spark (recommended)

Requires temporary network access on one Spark. Produces an image whose digest
you control and can rebuild.

```bash
# On the networked Spark, before airgapping:
git clone https://github.com/vllm-project/vllm.git && cd vllm
git checkout v0.17.0          # or the release the community reports working

# The SM121 MoE / Marlin / GDN patches referenced in the NVIDIA developer forum:
git clone https://github.com/namake-taro/vllm-custom /tmp/vllm-custom
for p in /tmp/vllm-custom/patches/*.patch; do
  echo "applying $p"; git apply --check "$p" && git apply "$p"
done

DOCKER_BUILDKIT=1 docker build \
  --build-arg CUDA_VERSION=13.0 \
  --build-arg torch_cuda_arch_list="12.1a" \
  --build-arg max_jobs=8 --build-arg nvcc_threads=4 \
  --target vllm-openai \
  -t sparksoc/vllm:0.17.0-sm121a \
  -f docker/Dockerfile .

docker save -o /tmp/vllm-sm121a.tar sparksoc/vllm:0.17.0-sm121a
sha256sum /tmp/vllm-sm121a.tar
```

Budget 60–120 minutes for the build. Copy the tar to the USB, update
`VLLM_IMAGE` in both `spark1/.env` and `spark2/.env`, and re-run the smoke gate
against the new image.

**Verify the patch set against the current forum thread before trusting it.**
Applying a third-party patch to an inference engine that will drive SOAR actions
deserves a read of the diff, not just `git apply`.

### Option B — stage a community GB10 prebuilt

Several maintained DGX Spark vLLM images exist. Pull with
`--platform linux/arm64`, run the smoke gate against it, and record the digest
in `MANIFEST.json`. Faster, but you are placing a third-party image inside a SOC
enclave — do the provenance review your organisation would require for any other
externally-sourced binary.

### Option C — pin an older official tag

Try `vllm/vllm-openai:v0.17.0` and other recent releases rather than the nightly
track. Cheap to test, and sometimes the nightly is simply broken that week.

---

## 8. If a specific stage fails

| Symptom | Cause | Fix |
|---|---|---|
| `hf: command not found` | old CLI | `pip install -U "huggingface_hub[cli]"` — `huggingface-cli` is deprecated |
| `401` on `hf download` | gated repo | accept the licence on the model page, `hf auth login` |
| `Architecture mismatch ... local store reports amd64` | legacy image store | enable containerd (§3), re-run with `-Force` |
| `does not publish linux/arm64` | image is x86-only | check the tag on Docker Hub; the alias may need changing |
| Wheelhouse: `error: command 'gcc' failed` | sdist needs a toolchain the slim image lacks | add the dev package to the `apt-get install` line in `Assets.ps1` |
| Wheelhouse very slow | qemu emulation | expected; 10–25 min is normal |
| `ATT&CK bundle is only 0.1 MB` | pinned URL 404s | check the filename at mitre-attack/attack-stix-data |
| `Shard index references N missing file(s)` | interrupted download | `-Stage Models -Force`; `hf download` resumes |
| Split parts fail to reassemble | copied with a tool that reordered them | `verify-bundle.sh` sorts with `sort -V`; check for truncated parts |

---

## 9. Next

Carry the media to the enclave, then run `verify-bundle.sh` on **each** target
host before extracting anything. Continue with
[`02-SPARK1-DEPLOY.md`](02-SPARK1-DEPLOY.md).
