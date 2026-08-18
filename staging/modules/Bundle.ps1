<#
.SYNOPSIS
    Pack staged artifacts into transfer bundles with checksums and split parts.
.NOTES
    Compression policy:
      Model weights are .safetensors — already dense binary. gzip buys ~1-2%
      and costs 30+ minutes of CPU on 135 GB. Those bundles are therefore
      written as uncompressed .tar. Everything else (code, ATT&CK JSON,
      wheels, image layer tars) compresses meaningfully and is written .tar.gz.
      Set -CompressModels to override.
#>

function New-TransferBundle {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SourceDir,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][hashtable]$Manifest,
        [switch]$Compress,
        [long]$SplitSizeBytes = 4079218688
    )

    if (-not (Test-Path -LiteralPath $SourceDir)) {
        Write-Log WARN "Source directory missing, skipping bundle '$Name': $SourceDir"
        return
    }

    $ext     = if ($Compress) { 'tar.gz' } else { 'tar' }
    $tarPath = Join-Path $OutputDir "$Name.$ext"

    Write-Log STEP "Bundle '$Name' <- $SourceDir  (compress=$($Compress.IsPresent))"

    if (Test-Path -LiteralPath $tarPath) { Remove-Item -LiteralPath $tarPath -Force }

    $parent = Split-Path -Parent $SourceDir
    $leaf   = Split-Path -Leaf   $SourceDir
    $flags  = if ($Compress) { '-czf' } else { '-cf' }

    # Windows 10+ ships bsdtar as tar.exe. -C keeps paths relative in the archive.
    Invoke-Native -FilePath 'tar' -Arguments @(
        $flags, $tarPath, '-C', $parent, $leaf
    ) -Context "tar $Name"

    $bytes  = (Get-Item -LiteralPath $tarPath).Length
    $sizeGB = [math]::Round($bytes / 1GB, 2)
    Write-Log INFO "Archive built: ${sizeGB} GB. Hashing..."
    $sha = Get-Sha256 -Path $tarPath
    Write-Log OK "sha256($Name.$ext) = $sha"

    $parts = @()
    if ($bytes -gt $SplitSizeBytes) {
        Write-Log INFO "Splitting into $([math]::Ceiling($bytes / $SplitSizeBytes)) parts of $([math]::Round($SplitSizeBytes/1GB,2)) GB..."
        $parts = Split-LargeFile -Path $tarPath -ChunkSize $SplitSizeBytes
        Remove-Item -LiteralPath $tarPath -Force
        Write-Log OK "Split complete; removed the unsplit archive to save space."
    }

    Add-ManifestEntry -Manifest $Manifest -Category 'bundles' -Entry @{
        name        = $Name
        file        = "$Name.$ext"
        compressed  = [bool]$Compress.IsPresent
        size_gb     = $sizeGB
        sha256      = $sha
        split       = ($parts.Count -gt 0)
        parts       = @($parts | ForEach-Object { @{ file = $_.Name; sha256 = $_.Sha256; bytes = $_.Bytes } })
        created_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Split-LargeFile {
    <#
    .SYNOPSIS
        Split a file into .partNNN chunks, hashing each as it is written.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$ChunkSize
    )

    $results  = @()
    $buffer   = New-Object byte[] (8MB)
    $srcInfo  = Get-Item -LiteralPath $Path
    $src      = [System.IO.File]::OpenRead($Path)
    $index    = 0

    try {
        while ($src.Position -lt $src.Length) {
            $index++
            $partPath = "{0}.part{1:D3}" -f $Path, $index
            $dst      = [System.IO.File]::Create($partPath)
            $sha      = [System.Security.Cryptography.SHA256]::Create()
            $written  = [long]0

            try {
                while ($written -lt $ChunkSize -and $src.Position -lt $src.Length) {
                    $want = [Math]::Min([long]$buffer.Length, $ChunkSize - $written)
                    $read = $src.Read($buffer, 0, [int]$want)
                    if ($read -le 0) { break }
                    $dst.Write($buffer, 0, $read)
                    $sha.TransformBlock($buffer, 0, $read, $null, 0) | Out-Null
                    $written += $read
                }
                $sha.TransformFinalBlock(@(), 0, 0) | Out-Null
                $hash = ($sha.Hash | ForEach-Object { $_.ToString('x2') }) -join ''
            }
            finally {
                $dst.Dispose(); $sha.Dispose()
            }

            $pct = [math]::Round(100 * $src.Position / $src.Length, 1)
            Write-Log INFO ("  part{0:D3}  {1} GB  {2}%  {3}" -f $index, [math]::Round($written/1GB,2), $pct, $hash.Substring(0,16))

            $results += [pscustomobject]@{
                Name   = Split-Path -Leaf $partPath
                Sha256 = $hash
                Bytes  = $written
            }
        }
    }
    finally { $src.Dispose() }

    return $results
}

function Write-BundleManifest {
    param(
        [Parameter(Mandatory)][hashtable]$Manifest,
        [Parameter(Mandatory)][string]$OutputDir
    )
    $path = Join-Path $OutputDir 'MANIFEST.json'
    $Manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding utf8
    Write-Log OK "Manifest written: $path"

    # Human-readable summary alongside the machine-readable manifest
    $summary = Join-Path $OutputDir 'MANIFEST.txt'
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("SPARKSOC transfer bundle $($Manifest.bundle_version)")
    [void]$sb.AppendLine("built $($Manifest.built_utc) on $($Manifest.built_host)")
    [void]$sb.AppendLine('')
    foreach ($cat in @('bundles','models','images','attack','wheelhouse')) {
        if (-not $Manifest.ContainsKey($cat)) { continue }
        [void]$sb.AppendLine("[$($cat.ToUpper())]")
        foreach ($e in $Manifest[$cat]) {
            $desc = if ($e.name) { $e.name } elseif ($e.alias) { $e.alias } elseif ($e.file) { $e.file } else { '?' }
            $size = if ($e.size_gb) { "$($e.size_gb) GB" } elseif ($e.size_mb) { "$($e.size_mb) MB" } else { '' }
            [void]$sb.AppendLine(("  {0,-28} {1,-12} {2}" -f $desc, $size, ($e.sha256 ?? $e.digest ?? '')))
        }
        [void]$sb.AppendLine('')
    }
    Set-Content -LiteralPath $summary -Value $sb.ToString() -Encoding utf8
    Write-Log OK "Summary written: $summary"
}

function Write-VerifyScript {
    <#
    .SYNOPSIS
        Emit the Linux-side verify+reassemble script that runs on each Spark.
    #>
    param([Parameter(Mandatory)][string]$OutputDir)

    $script = @'
#!/usr/bin/env bash
# verify-bundle.sh — run on the target host BEFORE loading anything.
# Reassembles split archives, verifies every SHA-256 against MANIFEST.json,
# and refuses to continue on any mismatch.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${HERE}/MANIFEST.json"

command -v jq >/dev/null 2>&1 || { echo "FATAL: jq required (stage it in the bundle)"; exit 1; }
[[ -f "$MANIFEST" ]] || { echo "FATAL: MANIFEST.json not found next to this script"; exit 1; }

echo "=== SPARKSOC bundle verification ==="
echo "bundle : $(jq -r .bundle_version "$MANIFEST")"
echo "built  : $(jq -r .built_utc "$MANIFEST")"
echo

fail=0

# ---- 1. Reassemble any split archives ------------------------------------
while read -r name file split; do
  if [[ "$split" == "true" ]]; then
    if [[ -f "${HERE}/${file}" ]]; then
      echo "[skip] ${file} already reassembled"
    else
      echo "[join] ${file} <- parts"
      # Numeric sort so part010 does not precede part002
      cat $(ls -1 "${HERE}/${file}".part* | sort -V) > "${HERE}/${file}"
    fi
  fi
done < <(jq -r '.bundles[] | "\(.name) \(.file) \(.split)"' "$MANIFEST")

# ---- 2. Verify archive checksums -----------------------------------------
echo
while read -r file want; do
  path="${HERE}/${file}"
  [[ -f "$path" ]] || { echo "[MISS] $file"; fail=1; continue; }
  printf '[hash] %-34s ' "$file"
  got=$(sha256sum "$path" | awk '{print $1}')
  if [[ "$got" == "$want" ]]; then
    echo "OK"
  else
    echo "MISMATCH"
    echo "         expected $want"
    echo "         got      $got"
    fail=1
  fi
done < <(jq -r '.bundles[] | "\(.file) \(.sha256)"' "$MANIFEST")

# ---- 3. Report the pinned image digests ----------------------------------
echo
echo "Pinned container image digests (verify after docker load):"
jq -r '.images[] | "  \(.alias)  \(.ref)  \(.digest // "UNPINNED")"' "$MANIFEST"

echo
if [[ $fail -ne 0 ]]; then
  echo "=== VERIFICATION FAILED — do not deploy this media ==="
  exit 1
fi
echo "=== VERIFICATION PASSED ==="
echo "Next: tar -xf <bundle>.tar -C /opt/sparksoc   (or tar -xzf for .tar.gz)"
'@ -replace "`r`n", "`n"

    $path = Join-Path $OutputDir 'verify-bundle.sh'
    [System.IO.File]::WriteAllText($path, $script, (New-Object System.Text.UTF8Encoding($false)))
    Write-Log OK "Verify script written: $path"
}

function Invoke-BundleStage {
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][hashtable]$Manifest,
        [switch]$CompressModels
    )
    Write-Log STEP '=== STAGE: BUNDLE ==='

    $outDir = New-StagingDirectory -Path (Join-Path $WorkRoot 'bundle')
    $split  = $Config.SplitSizeBytes

    # Deployment code: small, compresses well.
    $codeStage = New-StagingDirectory -Path (Join-Path $WorkRoot 'stage-code')
    foreach ($d in @('spark1','spark2','harness','splunk','validate','common','docs')) {
        $src = Join-Path $RepoRoot $d
        if (Test-Path $src) { Copy-Item -Recurse -Force -Path $src -Destination $codeStage }
    }
    Copy-Item -Force -Path (Join-Path $RepoRoot 'README.md') -Destination $codeStage -ErrorAction SilentlyContinue
    New-TransferBundle -Name 'sparksoc-code' -SourceDir $codeStage -OutputDir $outDir `
                       -Manifest $Manifest -Compress -SplitSizeBytes $split

    New-TransferBundle -Name 'sparksoc-images' -SourceDir (Join-Path $WorkRoot 'images') `
                       -OutputDir $outDir -Manifest $Manifest -Compress -SplitSizeBytes $split

    New-TransferBundle -Name 'sparksoc-attack' -SourceDir (Join-Path $WorkRoot 'attack') `
                       -OutputDir $outDir -Manifest $Manifest -Compress -SplitSizeBytes $split

    New-TransferBundle -Name 'sparksoc-wheelhouse' -SourceDir (Join-Path $WorkRoot 'wheelhouse') `
                       -OutputDir $outDir -Manifest $Manifest -Compress -SplitSizeBytes $split

    # Models: one bundle per node so each Spark only carries what it serves.
    if (-not $CompressModels) {
        Write-Log INFO 'Model bundles are UNCOMPRESSED .tar by design — safetensors do not gzip.'
        Write-Log INFO '  Use -CompressModels to override (expect ~1% savings for ~30 min CPU).'
    }
    $modelsRoot = Join-Path $WorkRoot 'models'
    foreach ($node in @('spark1','spark2')) {
        $nodeStage = Join-Path $WorkRoot "stage-models-$node"
        if (Test-Path $nodeStage) { Remove-Item -Recurse -Force $nodeStage }
        New-StagingDirectory -Path $nodeStage | Out-Null

        $any = $false
        foreach ($m in ($Config.Models | Where-Object { $_.Node -eq $node })) {
            $src = Join-Path $modelsRoot $m.LocalDir
            if (Test-Path $src) {
                Write-Log INFO "  linking $($m.LocalDir) into $node model bundle"
                # Junction avoids a second full copy of 70 GB.
                New-Item -ItemType Junction -Path (Join-Path $nodeStage $m.LocalDir) -Target $src -Force | Out-Null
                $any = $true
            }
        }
        if ($any) {
            New-TransferBundle -Name "sparksoc-models-$node" -SourceDir $nodeStage -OutputDir $outDir `
                               -Manifest $Manifest -Compress:$CompressModels -SplitSizeBytes $split
        }
    }

    Write-BundleManifest -Manifest $Manifest -OutputDir $outDir
    Write-VerifyScript -OutputDir $outDir

    Write-Log OK "Bundle staging directory ready: $outDir"
    Write-Log INFO 'Copy the entire directory to USB, then run verify-bundle.sh on each target host.'
}
