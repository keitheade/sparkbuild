<#
.SYNOPSIS
    MITRE ATT&CK STIX data and the offline aarch64 Python wheelhouse.
#>

# ---------------------------------------------------------------------------
# MITRE ATT&CK Enterprise STIX 2.1
# ---------------------------------------------------------------------------

function Invoke-AttackStage {
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][hashtable]$Manifest,
        [switch]$Force
    )
    Write-Log STEP '=== STAGE: MITRE ATT&CK STIX ==='

    $attackRoot = New-StagingDirectory -Path (Join-Path $WorkRoot 'attack')
    $dest = Join-Path $attackRoot $Config.Attack.FileName

    if ((Test-Path $dest) -and -not $Force) {
        Write-Log OK "ATT&CK bundle already present: $dest"
    } else {
        Write-Log INFO "Fetching $($Config.Attack.Version) from $($Config.Attack.Url)"
        $ProgressPreference = 'SilentlyContinue'   # ~40x faster for large files
        try {
            Invoke-WebRequest -Uri $Config.Attack.Url -OutFile $dest -UseBasicParsing -TimeoutSec 300
        } finally {
            $ProgressPreference = 'Continue'
        }
    }

    # ---- Validate it is a real STIX 2.1 bundle, not an HTML error page ----
    $sizeMB = [math]::Round((Get-Item -LiteralPath $dest).Length / 1MB, 1)
    if ($sizeMB -lt 5) {
        throw "ATT&CK bundle is only ${sizeMB} MB — that is almost certainly a 404 page. Check the pinned URL."
    }

    Write-Log INFO 'Parsing bundle (this takes ~10 s)...'
    $bundle = Get-Content -LiteralPath $dest -Raw | ConvertFrom-Json

    if ($bundle.type -ne 'bundle') {
        throw "Downloaded file is not a STIX bundle (type='$($bundle.type)')."
    }

    $counts = @{}
    foreach ($o in $bundle.objects) {
        if (-not $counts.ContainsKey($o.type)) { $counts[$o.type] = 0 }
        $counts[$o.type]++
    }

    $techniques = $counts['attack-pattern']
    if (-not $techniques -or $techniques -lt 500) {
        throw "Only $techniques attack-pattern objects found. Expected 600+. Bundle looks truncated."
    }

    Write-Log OK "STIX bundle valid: $($bundle.objects.Count) objects"
    foreach ($k in ($counts.Keys | Sort-Object)) {
        Write-Log INFO ("  {0,-24} {1}" -f $k, $counts[$k])
    }

    # Record the ATT&CK spec version if the bundle declares it
    $marking = $bundle.objects | Where-Object { $_.type -eq 'x-mitre-collection' } | Select-Object -First 1
    $attackVersion = if ($marking) { $marking.x_mitre_version } else { $Config.Attack.Version }

    Add-ManifestEntry -Manifest $Manifest -Category 'attack' -Entry @{
        file           = "attack/$($Config.Attack.FileName)"
        pinned_version = $Config.Attack.Version
        bundle_version = $attackVersion
        object_count   = $bundle.objects.Count
        technique_count = $techniques
        size_mb        = $sizeMB
        sha256         = (Get-Sha256 -Path $dest)
        source_url     = $Config.Attack.Url
    }
    Write-Log OK 'ATT&CK data staged.'
}

# ---------------------------------------------------------------------------
# Offline aarch64 Python wheelhouse
# ---------------------------------------------------------------------------

function Invoke-WheelhouseStage {
    <#
    .DESCRIPTION
        Builds wheels INSIDE a linux/arm64 container under qemu.

        Why not `pip download --platform manylinux_2_28_aarch64 --only-binary=:all:`?
        Because it silently skips any dependency that has no prebuilt aarch64
        wheel, and you discover the gap in the airgap. Building in-container
        compiles sdists for real, and fails loudly here instead.

        Cost: qemu emulation is slow. Budget 10-25 minutes.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][hashtable]$Manifest,
        [switch]$Force
    )
    Write-Log STEP '=== STAGE: AARCH64 PYTHON WHEELHOUSE ==='
    Assert-DockerReady

    $wheelRoot = New-StagingDirectory -Path (Join-Path $WorkRoot 'wheelhouse')
    $reqRoot   = New-StagingDirectory -Path (Join-Path $WorkRoot 'wheelhouse-req')

    if ((Get-ChildItem -LiteralPath $wheelRoot -Filter '*.whl' -ErrorAction SilentlyContinue).Count -gt 0 -and -not $Force) {
        Write-Log OK 'Wheelhouse already populated. Use -Force to rebuild.'
    }
    else {
        # Collect every requirements file into one place the container can see
        $combined = Join-Path $reqRoot 'all-requirements.txt'
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($rel in $Config.Wheelhouse.Sources) {
            $src = Join-Path $RepoRoot $rel
            if (-not (Test-Path $src)) {
                Write-Log WARN "Requirements file not found, skipping: $src"
                continue
            }
            Write-Log INFO "Including $rel"
            $lines.Add("# --- from $rel ---")
            $lines.AddRange([string[]](Get-Content -LiteralPath $src))
        }
        if ($lines.Count -eq 0) { throw 'No requirements files found. Nothing to build.' }
        Set-Content -LiteralPath $combined -Value $lines -Encoding utf8

        # Also stage pip/setuptools/wheel themselves so the Spark can bootstrap
        Add-Content -LiteralPath $combined -Value @(
            '', '# --- bootstrap ---', 'pip', 'setuptools', 'wheel'
        ) -Encoding utf8

        $wheelMount = (Resolve-Path $wheelRoot).Path
        $reqMount   = (Resolve-Path $reqRoot).Path

        $script = @'
set -euo pipefail
apt-get update -qq
apt-get install -y -qq --no-install-recommends build-essential python3-dev >/dev/null
python -m pip install --upgrade pip wheel setuptools
echo "--- building wheels for $(uname -m) ---"
python -m pip wheel \
    --wheel-dir /wheelhouse \
    --requirement /req/all-requirements.txt
echo "--- wheel count: $(ls -1 /wheelhouse/*.whl | wc -l) ---"
'@ -replace "`r`n", "`n"

        $scriptPath = Join-Path $reqRoot 'build.sh'
        [System.IO.File]::WriteAllText($scriptPath, $script, (New-Object System.Text.UTF8Encoding($false)))

        Write-Log INFO 'Building wheels under qemu — this is slow, expect 10-25 minutes.'
        Invoke-Native -FilePath 'docker' -Arguments @(
            'run', '--rm',
            '--platform', $Config.TargetPlatform,
            '-v', "${wheelMount}:/wheelhouse",
            '-v', "${reqMount}:/req",
            $Config.Wheelhouse.PythonImage,
            'bash', '/req/build.sh'
        ) -Context 'wheelhouse build'
    }

    $wheels = @(Get-ChildItem -LiteralPath $wheelRoot -Filter '*.whl' -File)
    if ($wheels.Count -eq 0) { throw 'Wheelhouse build produced no wheels.' }

    # Sanity: warn about any wheel that is x86_64 or a non-portable tag
    $bad = @($wheels | Where-Object { $_.Name -match 'x86_64|win_amd64|macosx' })
    if ($bad.Count -gt 0) {
        Write-Log WARN "$($bad.Count) wheel(s) have a non-aarch64 platform tag:"
        $bad | Select-Object -First 5 | ForEach-Object { Write-Log WARN "  $($_.Name)" }
    }

    $sizeMB = [math]::Round((($wheels | Measure-Object -Property Length -Sum).Sum) / 1MB, 1)
    Write-Log OK "Wheelhouse: $($wheels.Count) wheels, ${sizeMB} MB"

    Add-ManifestEntry -Manifest $Manifest -Category 'wheelhouse' -Entry @{
        path        = 'wheelhouse/'
        wheel_count = $wheels.Count
        size_mb     = $sizeMB
        python      = $Config.Wheelhouse.PythonImage
        platform    = $Config.TargetPlatform
        built_utc   = (Get-Date).ToUniversalTime().ToString('o')
    }
}
