<#
.SYNOPSIS
    Model weight acquisition via the Hugging Face CLI (`hf download`).
.NOTES
    Requires huggingface_hub >= 0.34 for the `hf` entrypoint.
    `huggingface-cli` is the deprecated alias and is NOT used here.
#>

function Assert-HuggingFaceCli {
    Assert-Command -Name 'hf' -InstallHint 'pip install -U "huggingface_hub[cli,hf_transfer]"'

    # hf_transfer materially speeds up 60+ GB pulls. Warn rather than fail.
    $env:HF_HUB_ENABLE_HF_TRANSFER = '1'
    Write-Log INFO 'HF_HUB_ENABLE_HF_TRANSFER=1 (falls back automatically if hf_transfer is absent)'

    if (-not $env:HF_TOKEN) {
        Write-Log WARN 'HF_TOKEN is not set. Gated repos will fail. Set it with:'
        Write-Log WARN '  $env:HF_TOKEN = "hf_..."   (or run: hf auth login)'
    }
}

function Get-ModelWeights {
    <#
    .SYNOPSIS
        Download one model repo into the staging tree.
    .DESCRIPTION
        Uses --local-dir so the result is a plain directory tree that can be
        tarred and mounted directly into the vLLM container on the Spark.
        Deliberately avoids the HF cache symlink layout, which does not
        survive tar/USB transfer cleanly.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Model,
        [Parameter(Mandatory)][string]$ModelsRoot,
        [Parameter(Mandatory)][hashtable]$Manifest,
        [switch]$Force
    )

    $dest = Join-Path $ModelsRoot $Model.LocalDir
    Write-Log STEP "Model '$($Model.Name)' — $($Model.RepoId) (~$($Model.ApproxGB) GB) -> $dest"

    $sentinel = Join-Path $dest '.sparksoc-complete'
    if ((Test-Path $sentinel) -and -not $Force) {
        Write-Log OK "Already downloaded (sentinel present). Use -Force to re-pull."
    }
    else {
        New-StagingDirectory -Path $dest | Out-Null

        $hfArgs = @(
            'download', $Model.RepoId,
            '--local-dir', $dest,
            '--max-workers', '8'
        )
        foreach ($pattern in $Model.Exclude) {
            $hfArgs += @('--exclude', $pattern)
        }

        # hf download is resumable; retry the whole invocation on transient failure.
        $attempt = 0
        $maxAttempts = 3
        while ($true) {
            $attempt++
            try {
                Invoke-Native -FilePath 'hf' -Arguments $hfArgs -Context "download $($Model.RepoId)"
                break
            }
            catch {
                if ($attempt -ge $maxAttempts) { throw }
                $wait = 15 * $attempt
                Write-Log WARN "Attempt $attempt failed: $($_.Exception.Message). Retrying in ${wait}s."
                Start-Sleep -Seconds $wait
            }
        }
        Set-Content -Path $sentinel -Value (Get-Date -Format o) -Encoding utf8
    }

    # ---- Validate the download actually looks like a servable model ----
    $configPath = Join-Path $dest 'config.json'
    if (-not (Test-Path $configPath)) {
        throw "No config.json in $dest — download is incomplete or the repo id is wrong."
    }

    $weights = @(Get-ChildItem -LiteralPath $dest -Filter '*.safetensors' -Recurse -File)
    if ($weights.Count -eq 0) {
        throw "No .safetensors shards in $dest. vLLM cannot serve this. Check --exclude patterns."
    }

    $indexPath = Join-Path $dest 'model.safetensors.index.json'
    if (Test-Path $indexPath) {
        $index = Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json
        $expected = @($index.weight_map.PSObject.Properties.Value | Sort-Object -Unique)
        $present  = @($weights | ForEach-Object { $_.Name } | Sort-Object -Unique)
        $missing  = @($expected | Where-Object { $_ -notin $present })
        if ($missing.Count -gt 0) {
            throw "Shard index references $($missing.Count) missing file(s), first: $($missing[0])"
        }
        Write-Log OK "Shard index complete: $($expected.Count) shards accounted for."
    }

    $totalBytes = ($weights | Measure-Object -Property Length -Sum).Sum
    $totalGB    = [math]::Round($totalBytes / 1GB, 2)
    Write-Log OK "$($Model.Name): $($weights.Count) shards, ${totalGB} GB"

    # Report the quantization vLLM will auto-detect, so surprises surface now.
    $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $quant = $null
    if ($cfg.PSObject.Properties.Name -contains 'quantization_config') {
        $quant = $cfg.quantization_config.quant_method
        Write-Log INFO "Detected quantization_config.quant_method = '$quant'"
        Write-Log INFO "  -> do NOT pass --quantization on the vLLM command line for this model"
    } else {
        Write-Log INFO "No quantization_config — weights are full precision; vLLM will quantize online if asked."
    }

    Add-ManifestEntry -Manifest $Manifest -Category 'models' -Entry @{
        name        = $Model.Name
        repo_id     = $Model.RepoId
        local_dir   = $Model.LocalDir
        node        = $Model.Node
        shard_count = $weights.Count
        size_gb     = $totalGB
        quant_method = $quant
        downloaded_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Invoke-ModelStage {
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][hashtable]$Manifest,
        [switch]$Force
    )
    Write-Log STEP '=== STAGE: MODELS ==='
    Assert-HuggingFaceCli

    $required = ($Config.Models | Measure-Object -Property ApproxGB -Sum).Sum
    Assert-FreeSpace -Path $WorkRoot -RequiredGB ([int]($required * 1.3))

    $modelsRoot = New-StagingDirectory -Path (Join-Path $WorkRoot 'models')
    foreach ($m in $Config.Models) {
        Get-ModelWeights -Model $m -ModelsRoot $modelsRoot -Manifest $Manifest -Force:$Force
    }
    Write-Log OK 'All model weights staged.'
}
