<#
.SYNOPSIS
    SPARKSOC staging orchestrator. Builds a complete airgap transfer bundle on a
    Windows 11 x86_64 host: model weights, linux/arm64 container images, MITRE
    ATT&CK STIX data, an aarch64 Python wheelhouse, and the deployment code.

.DESCRIPTION
    Stages run in order and are individually resumable. Each writes into
    $Config.WorkRoot and appends to MANIFEST.json.

      Preflight   prerequisites, disk, USB filesystem
      Models      hf download of the three model repos
      Images      docker pull --platform linux/arm64 + docker save
      Attack      MITRE ATT&CK Enterprise STIX 2.1
      Wheelhouse  pip wheel inside an arm64 container (qemu)
      Smoke       MANDATORY GATE - validate the vLLM image on real GB10 hardware
      Bundle      tar + split + checksum + verify script

.PARAMETER Stage
    Which stages to run. Default: All.

.PARAMETER SkipSmokeGate
    Bypass the hardware validation gate. You are choosing to deploy an
    unvalidated runtime into an airgap. See docs/01-STAGING.md section 7.

.EXAMPLE
    .\Stage-SOCBundle.ps1
    Full run.

.EXAMPLE
    .\Stage-SOCBundle.ps1 -Stage Images,Smoke -Force
    Re-pull images and re-run the hardware gate only.

.NOTES
    Run from an elevated PowerShell 7+ prompt. Budget 4-8 hours and ~400 GB
    of working disk for a cold run.
#>

[CmdletBinding()]
param(
    [ValidateSet('All','Preflight','Models','Images','Attack','Wheelhouse','Smoke','Bundle')]
    [string[]]$Stage = @('All'),

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\staging.psd1'),

    [switch]$Force,
    [switch]$SkipSmokeGate,
    [switch]$CompressModels
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Load modules
# ---------------------------------------------------------------------------
foreach ($mod in @('Common','Models','Images','Assets','Bundle')) {
    . (Join-Path $PSScriptRoot "modules\$mod.ps1")
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host 'PowerShell 7+ is required (this script uses ?? and ternary operators).' -ForegroundColor Red
    Write-Host 'Install: winget install Microsoft.PowerShell' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Config not found: $ConfigPath" }
$Config   = Import-PowerShellDataFile -LiteralPath $ConfigPath
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$WorkRoot = New-StagingDirectory -Path $Config.WorkRoot

Initialize-StagingLog -WorkRoot $WorkRoot

Write-Log STEP '========================================================='
Write-Log STEP "  SPARKSOC staging $($Config.BundleVersion)"
Write-Log STEP "  repo      : $RepoRoot"
Write-Log STEP "  work root : $WorkRoot"
Write-Log STEP "  usb root  : $($Config.UsbRoot)"
Write-Log STEP "  platform  : $($Config.TargetPlatform)"
Write-Log STEP '========================================================='

$runAll = $Stage -contains 'All'
function Test-StageSelected([string]$name) { return ($runAll -or ($Stage -contains $name)) }

# ---------------------------------------------------------------------------
# Manifest — resumable across runs
# ---------------------------------------------------------------------------
$manifestPath = Join-Path $WorkRoot 'MANIFEST.json'
$Manifest = @{}
if ((Test-Path $manifestPath) -and -not $Force) {
    Write-Log INFO 'Resuming from existing MANIFEST.json'
    $existing = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    foreach ($p in $existing.PSObject.Properties) {
        $Manifest[$p.Name] = if ($p.Value -is [array]) { @($p.Value | ForEach-Object {
            $h=@{}; $_.PSObject.Properties | ForEach-Object { $h[$_.Name]=$_.Value }; $h }) } else { $p.Value }
    }
}
$Manifest['bundle_version'] = $Config.BundleVersion
$Manifest['built_utc']      = (Get-Date).ToUniversalTime().ToString('o')
$Manifest['built_host']     = $env:COMPUTERNAME
$Manifest['target_platform']= $Config.TargetPlatform

function Save-Progress {
    $Manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding utf8
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    # -----------------------------------------------------------------------
    # PREFLIGHT
    # -----------------------------------------------------------------------
    if (Test-StageSelected 'Preflight') {
        Write-Log STEP '=== STAGE: PREFLIGHT ==='
        Assert-Command -Name 'tar'    -InstallHint 'Built into Windows 10 1803+ as tar.exe'
        Assert-Command -Name 'docker' -InstallHint 'Docker Desktop for Windows'
        Assert-Command -Name 'hf'     -InstallHint 'pip install -U "huggingface_hub[cli,hf_transfer]"'

        $modelGB = ($Config.Models | Measure-Object -Property ApproxGB -Sum).Sum
        # weights + image tars + wheelhouse + bundle copy
        $needGB  = [int](($modelGB * 2.2) + 60)
        Assert-FreeSpace -Path $WorkRoot -RequiredGB $needGB
        Test-UsbFileSystem -UsbRoot $Config.UsbRoot

        Write-Log OK 'Preflight passed.'
        Save-Progress
    }

    if (Test-StageSelected 'Models')     { Invoke-ModelStage      -Config $Config -WorkRoot $WorkRoot -Manifest $Manifest -Force:$Force; Save-Progress }
    if (Test-StageSelected 'Images')     { Invoke-ImageStage      -Config $Config -WorkRoot $WorkRoot -Manifest $Manifest -Force:$Force; Save-Progress }
    if (Test-StageSelected 'Attack')     { Invoke-AttackStage     -Config $Config -WorkRoot $WorkRoot -Manifest $Manifest -Force:$Force; Save-Progress }
    if (Test-StageSelected 'Wheelhouse') { Invoke-WheelhouseStage -Config $Config -WorkRoot $WorkRoot -RepoRoot $RepoRoot -Manifest $Manifest -Force:$Force; Save-Progress }

    # -----------------------------------------------------------------------
    # SMOKE GATE — the reason this build does not fail inside the enclave
    # -----------------------------------------------------------------------
    if (Test-StageSelected 'Smoke') {
        Write-Log STEP '=== STAGE: HARDWARE SMOKE GATE ==='
        if ($SkipSmokeGate -or -not $Config.SmokeGate.Enabled) {
            Write-Log WARN '################################################################'
            Write-Log WARN '# SMOKE GATE SKIPPED                                           #'
            Write-Log WARN '#                                                              #'
            Write-Log WARN '# You are shipping vllm/vllm-openai:cu130-nightly into an      #'
            Write-Log WARN '# airgap without confirming it has sm_121 aarch64 kernels.     #'
            Write-Log WARN '# Official vLLM builds are not guaranteed to (vLLM #36821),    #'
            Write-Log WARN '# and gpt-oss at TP=1 on SM121 has a known Marlin MoE bug      #'
            Write-Log WARN '# that emits a null first Harmony token (vLLM #37030).         #'
            Write-Log WARN '#                                                              #'
            Write-Log WARN '# Fallback if it fails on the Spark: docs/01-STAGING.md sec 7  #'
            Write-Log WARN '################################################################'
            $Manifest['smoke_gate'] = @{ status = 'skipped'; utc = (Get-Date).ToUniversalTime().ToString('o') }
        }
        else {
            $smokeScript = Join-Path $PSScriptRoot 'Test-SparkSmoke.ps1'
            $result = & $smokeScript -Config $Config -WorkRoot $WorkRoot
            $Manifest['smoke_gate'] = $result
            if ($result.status -ne 'pass') {
                throw "Smoke gate FAILED: $($result.summary). Refusing to bundle. See docs/01-STAGING.md section 7."
            }
            Write-Log OK 'Smoke gate PASSED — runtime validated on real GB10 hardware.'
        }
        Save-Progress
    }

    if (Test-StageSelected 'Bundle') {
        Invoke-BundleStage -Config $Config -WorkRoot $WorkRoot -RepoRoot $RepoRoot `
                           -Manifest $Manifest -CompressModels:$CompressModels
        Save-Progress
    }

    $stopwatch.Stop()
    Write-Log OK '========================================================='
    Write-Log OK "  STAGING COMPLETE in $($stopwatch.Elapsed.ToString('hh\:mm\:ss'))"
    Write-Log OK "  Bundle: $(Join-Path $WorkRoot 'bundle')"
    Write-Log OK '========================================================='
    Write-Log INFO ''
    Write-Log INFO 'Next steps:'
    Write-Log INFO "  1. robocopy `"$(Join-Path $WorkRoot 'bundle')`" `"$($Config.UsbRoot)`" /E /J /R:2 /W:5"
    Write-Log INFO '  2. Eject, carry to the enclave.'
    Write-Log INFO '  3. On each target: bash verify-bundle.sh'
    Write-Log INFO '  4. Follow docs/02-SPARK1-DEPLOY.md'
}
catch {
    Write-Log ERROR "STAGING FAILED: $($_.Exception.Message)"
    Write-Log ERROR $_.ScriptStackTrace
    Save-Progress
    exit 1
}
