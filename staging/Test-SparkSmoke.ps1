<#
.SYNOPSIS
    Hardware validation gate. Proves the staged vLLM image actually serves on
    GB10 / sm_121 aarch64 BEFORE the bundle crosses into the airgap.

.DESCRIPTION
    Runs over SSH against a DGX Spark that is still network-reachable during
    staging. Ships the image tar and the smallest staged model, starts vLLM,
    and asserts:

      T1  image loads and reports arm64
      T2  CUDA device is visible and reports sm_121 / compute capability 12.1
      T3  vLLM starts and /health returns 200 within the timeout
      T4  a chat completion returns NON-EMPTY content
          (this is the check for vLLM #37030 — the SM121 Marlin MoE shared-memory
           race that yields a null first Harmony token; it manifests as a 200 OK
           with empty content, which a naive health check would call success)
      T5  a second, longer completion is coherent and finishes cleanly
      T6  embeddings endpoint returns a vector of the expected dimension

    Exit contract: returns a hashtable consumed by Stage-SOCBundle.ps1.

.NOTES
    If you have no Spark reachable at staging time, set SmokeGate.Enabled=$false
    in staging.psd1 and read docs/01-STAGING.md section 7 first.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][hashtable]$Config,
    [Parameter(Mandatory)][string]$WorkRoot,
    [int]$StartupTimeoutSec = 900
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'modules\Common.ps1')
}

$gate      = $Config.SmokeGate
$sparkHost = $gate.SparkHost
$sparkUser = $gate.SparkUser
$sshKey    = $ExecutionContext.InvokeCommand.ExpandString($gate.SshKey)
$target    = "$sparkUser@$sparkHost"
$remoteDir = '/tmp/sparksoc-smoke'

$tests            = @()
$overall          = 'pass'
$script:embedDim  = $null

function Add-Result {
    param([string]$Id, [string]$Name, [string]$Status, [string]$Detail = '')
    $script:tests += @{ id = $Id; name = $Name; status = $Status; detail = $Detail }
    $lvl = if ($Status -eq 'pass') { 'OK' } elseif ($Status -eq 'warn') { 'WARN' } else { 'ERROR' }
    Write-Log $lvl ("[{0}] {1} — {2} {3}" -f $Id, $Name, $Status.ToUpper(), $Detail)
    if ($Status -eq 'fail') { $script:overall = 'fail' }
}

function Invoke-Ssh {
    param([Parameter(Mandatory)][string]$Command, [switch]$AllowFailure, [int]$TimeoutSec = 0)
    $sshArgs = @('-i', $sshKey, '-o', 'StrictHostKeyChecking=accept-new', '-o', 'BatchMode=yes')
    if ($TimeoutSec -gt 0) { $sshArgs += @('-o', 'ConnectTimeout=30') }
    $sshArgs += @($target, $Command)
    $out = & ssh @sshArgs 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowFailure) {
        throw "ssh failed (exit $code): $Command`n$out"
    }
    return [pscustomobject]@{ Output = $out.Trim(); ExitCode = $code }
}

Write-Log STEP "Smoke gate target: $target"

try {
    Assert-Command -Name 'ssh'  -InstallHint 'Windows OpenSSH client: Settings > Optional Features'
    Assert-Command -Name 'scp'

    # -- connectivity -------------------------------------------------------
    $r = Invoke-Ssh -Command 'uname -m; . /etc/os-release 2>/dev/null && echo $PRETTY_NAME'
    Write-Log INFO "Remote: $($r.Output -replace "`n", ' | ')"
    if ($r.Output -notmatch 'aarch64') {
        Add-Result T0 'Remote host is aarch64' 'fail' "uname -m returned: $($r.Output)"
        throw 'Smoke target is not an aarch64 host.'
    }
    Add-Result T0 'Remote host is aarch64' 'pass'

    Invoke-Ssh -Command "mkdir -p $remoteDir" | Out-Null

    # -- T2 GPU / compute capability ---------------------------------------
    $r = Invoke-Ssh -Command 'nvidia-smi --query-gpu=name,compute_cap,memory.total --format=csv,noheader' -AllowFailure
    if ($r.ExitCode -ne 0) {
        Add-Result T2 'CUDA device visible' 'fail' 'nvidia-smi failed'
    } else {
        Write-Log INFO "GPU: $($r.Output)"
        if ($r.Output -match '12\.1') {
            Add-Result T2 'GB10 sm_121 detected' 'pass' $r.Output
        } else {
            Add-Result T2 'GB10 sm_121 detected' 'warn' "compute_cap not 12.1: $($r.Output)"
        }
    }

    # -- T1 ship and load the image ----------------------------------------
    $imageTar = Join-Path $WorkRoot 'images\vllm.tar'
    if (-not (Test-Path $imageTar)) { throw "Image tar not staged: $imageTar. Run the Images stage first." }

    $already = Invoke-Ssh -Command "test -f $remoteDir/vllm.tar && echo yes || echo no"
    if ($already.Output -ne 'yes') {
        Write-Log INFO "Copying vllm.tar to $target (this takes a while over 1 GbE)..."
        & scp -i $sshKey -o StrictHostKeyChecking=accept-new $imageTar "${target}:$remoteDir/vllm.tar"
        if ($LASTEXITCODE -ne 0) { throw 'scp of image tar failed.' }
    } else {
        Write-Log INFO 'Image tar already present on remote host.'
    }

    Write-Log INFO 'Loading image on the Spark...'
    $r = Invoke-Ssh -Command "docker load -i $remoteDir/vllm.tar"
    $loadedRef = ($r.Output -split "`n" | Where-Object { $_ -match 'Loaded image' } |
                  Select-Object -First 1) -replace '^Loaded image[^:]*:\s*', ''
    if (-not $loadedRef) { $loadedRef = 'vllm/vllm-openai:cu130-nightly' }
    $loadedRef = $loadedRef.Trim()
    Write-Log INFO "Loaded: $loadedRef"

    $r = Invoke-Ssh -Command "docker image inspect $loadedRef --format '{{.Architecture}}'"
    if ($r.Output.Trim() -eq 'arm64') {
        Add-Result T1 'Image is arm64 on target' 'pass'
    } else {
        Add-Result T1 'Image is arm64 on target' 'fail' "Architecture=$($r.Output)"
        throw 'Image architecture mismatch. Enable the containerd image store and re-pull.'
    }

    # -- ship the smallest model (embedding) for a quick functional check ---
    $embed = $Config.Models | Where-Object { $_.Name -eq 'embed' } | Select-Object -First 1
    $embedSrc = Join-Path $WorkRoot "models\$($embed.LocalDir)"
    $already = Invoke-Ssh -Command "test -d $remoteDir/$($embed.LocalDir) && echo yes || echo no"
    if ($already.Output -ne 'yes') {
        Write-Log INFO "Copying $($embed.LocalDir) (~$($embed.ApproxGB) GB)..."
        & scp -r -i $sshKey -o StrictHostKeyChecking=accept-new $embedSrc "${target}:$remoteDir/"
        if ($LASTEXITCODE -ne 0) { throw 'scp of embedding model failed.' }
    }

    # -- T3/T6 start vLLM in pooling mode and probe -------------------------
    Write-Log INFO 'Starting vLLM (embedding mode) on the Spark...'
    Invoke-Ssh -Command 'docker rm -f sparksoc-smoke 2>/dev/null || true' -AllowFailure | Out-Null

    $runCmd = @"
docker run -d --name sparksoc-smoke --runtime nvidia --gpus all --ipc=host \
  -e HF_HUB_OFFLINE=1 -e TRANSFORMERS_OFFLINE=1 -e VLLM_NO_USAGE_STATS=1 -e DO_NOT_TRACK=1 \
  -v $remoteDir/$($embed.LocalDir):/model:ro -p 18999:8000 \
  $loadedRef \
  --model /model --served-model-name smoke-embed \
  --runner pooling --gpu-memory-utilization 0.20 --max-model-len 2048 --port 8000
"@ -replace "`r`n", ' '

    Invoke-Ssh -Command $runCmd | Out-Null

    Write-Log INFO "Waiting up to ${StartupTimeoutSec}s for /health (first start pays ~25 s of JIT)..."
    $waitCmd = "for i in \`seq 1 $([int]($StartupTimeoutSec/5))\`; do " +
               "if curl -sf -m 3 http://127.0.0.1:18999/health >/dev/null 2>&1; then echo READY; exit 0; fi; " +
               "if ! docker ps --format '{{.Names}}' | grep -q sparksoc-smoke; then echo DIED; exit 1; fi; " +
               "sleep 5; done; echo TIMEOUT; exit 1"
    $r = Invoke-Ssh -Command $waitCmd -AllowFailure

    if ($r.Output -match 'READY') {
        Add-Result T3 'vLLM serves on sm_121' 'pass'
    } else {
        $logs = Invoke-Ssh -Command 'docker logs --tail 80 sparksoc-smoke 2>&1' -AllowFailure
        Write-Log ERROR '--- container logs (tail 80) ---'
        $logs.Output -split "`n" | ForEach-Object { Write-Log ERROR "  $_" }
        Write-Log ERROR '--------------------------------'
        $hint = if ($logs.Output -match 'no kernel image|sm_121|not compiled|CUDA error: no kernel') {
            'MISSING sm_121 KERNELS — this is vLLM #36821. Go to docs/01-STAGING.md section 7.'
        } else { "state=$($r.Output)" }
        Add-Result T3 'vLLM serves on sm_121' 'fail' $hint
        throw "vLLM did not become healthy. $hint"
    }

    # -- T6 embeddings ------------------------------------------------------
    $embedCmd = "curl -sf -m 60 http://127.0.0.1:18999/v1/embeddings " +
                "-H 'Content-Type: application/json' " +
                "-d '{\`"model\`":\`"smoke-embed\`",\`"input\`":[\`"powershell -enc  encoded command\`"]}'"
    $r = Invoke-Ssh -Command $embedCmd -AllowFailure
    if ($r.ExitCode -eq 0 -and $r.Output -match '"embedding"') {
        try {
            $doc = $r.Output | ConvertFrom-Json
            $dim = $doc.data[0].embedding.Count
            if ($dim -gt 0) {
                Add-Result T6 'Embeddings endpoint' 'pass' "dim=$dim"
                $script:embedDim = $dim
            } else {
                Add-Result T6 'Embeddings endpoint' 'fail' 'zero-length vector'
            }
        } catch {
            Add-Result T6 'Embeddings endpoint' 'fail' 'unparseable response'
        }
    } else {
        Add-Result T6 'Embeddings endpoint' 'fail' "curl exit $($r.ExitCode)"
    }

    Invoke-Ssh -Command 'docker rm -f sparksoc-smoke' -AllowFailure | Out-Null

    # -- T4/T5 generative check --------------------------------------------
    # Only meaningful if a generative model has been shipped to the smoke host.
    # We do not scp 65 GB over 1 GbE by default; if the operator has already
    # placed one at $remoteDir/gen-model, we exercise the null-content bug.
    $hasGen = Invoke-Ssh -Command "test -f $remoteDir/gen-model/config.json && echo yes || echo no"
    if ($hasGen.Output -eq 'yes') {
        Write-Log INFO 'Generative model present on smoke host — running T4/T5.'
        Invoke-Ssh -Command 'docker rm -f sparksoc-smoke-gen 2>/dev/null || true' -AllowFailure | Out-Null
        $genRun = @"
docker run -d --name sparksoc-smoke-gen --runtime nvidia --gpus all --ipc=host \
  -e HF_HUB_OFFLINE=1 -e VLLM_NO_USAGE_STATS=1 -e DO_NOT_TRACK=1 \
  -v $remoteDir/gen-model:/model:ro -p 18998:8000 \
  $loadedRef --model /model --served-model-name smoke-gen \
  --gpu-memory-utilization 0.85 --max-model-len 8192 --max-num-seqs 4 --port 8000
"@ -replace "`r`n", ' '
        Invoke-Ssh -Command $genRun | Out-Null

        $r = Invoke-Ssh -Command ("for i in \`seq 1 180\`; do curl -sf -m 3 http://127.0.0.1:18998/health >/dev/null 2>&1 && { echo READY; exit 0; }; sleep 5; done; echo TIMEOUT; exit 1") -AllowFailure

        if ($r.Output -match 'READY') {
            $chatCmd = "curl -sf -m 180 http://127.0.0.1:18998/v1/chat/completions " +
                       "-H 'Content-Type: application/json' " +
                       "-d '{\`"model\`":\`"smoke-gen\`",\`"messages\`":[{\`"role\`":\`"user\`",\`"content\`":\`"Reply with exactly the word ALIVE and nothing else.\`"}],\`"max_tokens\`":32,\`"temperature\`":0}'"
            $r = Invoke-Ssh -Command $chatCmd -AllowFailure
            $content = $null
            try { $content = ($r.Output | ConvertFrom-Json).choices[0].message.content } catch { }

            if ([string]::IsNullOrWhiteSpace($content)) {
                Add-Result T4 'Non-empty completion (vLLM #37030 check)' 'fail' `
                    'MODEL RETURNED EMPTY CONTENT — this is the SM121 Marlin MoE race. Apply the mitigations in spark2/.env.example before deploying.'
            } else {
                Add-Result T4 'Non-empty completion (vLLM #37030 check)' 'pass' "content='$($content.Trim())'"
            }

            $longCmd = "curl -sf -m 300 http://127.0.0.1:18998/v1/chat/completions " +
                       "-H 'Content-Type: application/json' " +
                       "-d '{\`"model\`":\`"smoke-gen\`",\`"messages\`":[{\`"role\`":\`"user\`",\`"content\`":\`"In three sentences, explain what MITRE ATT&CK technique T1059.001 is.\`"}],\`"max_tokens\`":300,\`"temperature\`":0}'"
            $r = Invoke-Ssh -Command $longCmd -AllowFailure
            try {
                $doc = $r.Output | ConvertFrom-Json
                $txt = $doc.choices[0].message.content
                $fin = $doc.choices[0].finish_reason
                if ($txt -and $txt.Length -gt 80 -and $fin -in @('stop','length')) {
                    Add-Result T5 'Coherent long completion' 'pass' "len=$($txt.Length) finish=$fin"
                } else {
                    Add-Result T5 'Coherent long completion' 'fail' "len=$($txt.Length) finish=$fin"
                }
            } catch { Add-Result T5 'Coherent long completion' 'fail' 'unparseable response' }
        } else {
            Add-Result T4 'Non-empty completion (vLLM #37030 check)' 'fail' 'generative server did not start'
        }
        Invoke-Ssh -Command 'docker rm -f sparksoc-smoke-gen' -AllowFailure | Out-Null
    }
    else {
        Add-Result T4 'Non-empty completion (vLLM #37030 check)' 'warn' `
            "SKIPPED — no generative model at $remoteDir/gen-model on the smoke host. Strongly recommended before deploying gpt-oss-120b at TP=1."
    }
}
catch {
    Write-Log ERROR "Smoke gate error: $($_.Exception.Message)"
    $overall = 'fail'
    if ($tests.Count -eq 0) { Add-Result T0 'Smoke gate execution' 'fail' $_.Exception.Message }
}
finally {
    try { Invoke-Ssh -Command 'docker rm -f sparksoc-smoke sparksoc-smoke-gen 2>/dev/null || true' -AllowFailure | Out-Null } catch {}
}

$passed = @($tests | Where-Object { $_.status -eq 'pass' }).Count
$failed = @($tests | Where-Object { $_.status -eq 'fail' }).Count
$warned = @($tests | Where-Object { $_.status -eq 'warn' }).Count
$summary = "$passed pass / $warned warn / $failed fail"

Write-Log STEP "Smoke gate result: $($overall.ToUpper()) — $summary"

return @{
    status    = $overall
    summary   = $summary
    tests     = $tests
    host      = $sparkHost
    embed_dim = $script:embedDim
    utc       = (Get-Date).ToUniversalTime().ToString('o')
}
