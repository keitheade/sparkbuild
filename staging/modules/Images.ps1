<#
.SYNOPSIS
    Multi-arch container image acquisition for linux/arm64 from an x86_64 host.
.NOTES
    Pulling a foreign-architecture image on Windows works, but two things must
    be true or you will discover the problem on the Spark instead of here:

      1. The tag must actually publish a linux/arm64 manifest. Many CUDA
         images are x86-only. We verify with `docker buildx imagetools inspect`
         BEFORE pulling.
      2. The local image store must retain the foreign architecture. Docker
         Desktop's containerd image store handles this correctly; the legacy
         image store also works for pull+save but is less predictable with
         multi-platform manifests. We verify post-pull via
         `docker image inspect --format {{.Architecture}}`.
#>

function Assert-DockerReady {
    Assert-Command -Name 'docker' -InstallHint 'Install Docker Desktop for Windows and enable it'

    try {
        $info = docker info --format '{{json .}}' 2>$null | ConvertFrom-Json
    } catch {
        throw 'docker info failed. Is Docker Desktop running?'
    }
    Write-Log OK "Docker server $($info.ServerVersion) on $($info.OSType)/$($info.Architecture)"

    # containerd image store is strongly preferred for multi-arch save/load.
    # Probe defensively: Set-StrictMode makes a missing property fatal.
    $hasContainerd = $false
    if ($info.PSObject.Properties.Name -contains 'Features' -and $info.Features) {
        if ($info.Features.PSObject.Properties.Name -contains 'containerd_snapshotter') {
            $hasContainerd = [bool]$info.Features.containerd_snapshotter
        }
    }
    if ($hasContainerd) {
        Write-Log OK 'containerd image store is enabled (recommended for multi-arch).'
    } else {
        Write-Log WARN 'containerd image store does NOT appear to be enabled.'
        Write-Log WARN '  Docker Desktop > Settings > General > "Use containerd for pulling and storing images"'
        Write-Log WARN '  Without it, `docker save` of a foreign-arch image can silently emit the host arch.'
        Write-Log WARN '  The post-pull architecture assertion below will catch that, but enable it anyway.'
    }

    # binfmt/qemu is needed later for the wheelhouse build, not for pull+save.
    Write-Log INFO 'Verifying qemu binfmt for linux/arm64 (needed by the wheelhouse stage)...'
    $rc = Invoke-Native -FilePath 'docker' -Arguments @(
        'run','--rm','--platform','linux/arm64','alpine:3.20','uname','-m'
    ) -AllowFailure
    if ($rc -ne 0) {
        Write-Log WARN 'Could not run an arm64 container. Install emulators with:'
        Write-Log WARN '  docker run --privileged --rm tonistiigi/binfmt --install arm64'
    } else {
        Write-Log OK 'qemu arm64 emulation is functional.'
    }
}

function Get-ImagePlatforms {
    <#
    .SYNOPSIS
        Enumerate platforms published for a tag without pulling it.
    .OUTPUTS
        Array of 'os/arch' strings, or $null if the registry could not be queried.
    #>
    param([Parameter(Mandatory)][string]$Ref)

    $raw = docker buildx imagetools inspect $Ref --raw 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) {
        Write-Log WARN "buildx imagetools inspect failed for $Ref; trying docker manifest inspect."
        $raw = docker manifest inspect $Ref 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            Write-Log WARN "Could not enumerate platforms for $Ref."
            return $null
        }
    }

    try { $doc = $raw | ConvertFrom-Json } catch { return $null }

    if ($doc.PSObject.Properties.Name -contains 'manifests') {
        return @(
            $doc.manifests |
                Where-Object { $_.platform -and $_.platform.os -ne 'unknown' } |
                ForEach-Object { "$($_.platform.os)/$($_.platform.architecture)" } |
                Sort-Object -Unique
        )
    }
    # Single-platform image (no manifest list)
    return @('single-platform')
}

function Get-ContainerImage {
    param(
        [Parameter(Mandatory)][hashtable]$Image,
        [Parameter(Mandatory)][string]$Platform,
        [Parameter(Mandatory)][string]$ImagesRoot,
        [Parameter(Mandatory)][hashtable]$Manifest,
        [switch]$Force
    )

    $ref   = $Image.Ref
    $alias = $Image.Alias
    Write-Log STEP "Image '$alias' — $ref ($Platform)"

    # ---- 1. Confirm the platform exists upstream -------------------------
    $platforms = Get-ImagePlatforms -Ref $ref
    if ($platforms) {
        Write-Log INFO "Published platforms: $($platforms -join ', ')"
        if ($platforms -notcontains $Platform -and $platforms -notcontains 'single-platform') {
            $msg = "$ref does not publish $Platform. Published: $($platforms -join ', ')"
            if ($Image.Critical) { throw $msg }
            Write-Log WARN $msg
            return
        }
    }

    # ---- 2. Resolve and pin the digest -----------------------------------
    $digest = $null
    $rawList = docker buildx imagetools inspect $ref --raw 2>$null
    if ($LASTEXITCODE -eq 0 -and $rawList) {
        try {
            $doc = $rawList | ConvertFrom-Json
            $arch = ($Platform -split '/')[1]
            $entry = $doc.manifests | Where-Object {
                $_.platform.os -eq 'linux' -and $_.platform.architecture -eq $arch
            } | Select-Object -First 1
            if ($entry) { $digest = $entry.digest }
        } catch { }
    }
    if ($digest) {
        Write-Log OK "Pinned $Platform digest: $digest"
    } else {
        Write-Log WARN "Could not resolve a platform digest for $ref. Tag will be recorded unpinned."
    }

    $tarPath = Join-Path $ImagesRoot "$alias.tar"

    if ((Test-Path $tarPath) -and -not $Force) {
        Write-Log OK "Image tar already present: $tarPath (use -Force to re-pull)"
    }
    else {
        # ---- 3. Pull for the target platform ------------------------------
        Invoke-Native -FilePath 'docker' -Arguments @(
            'pull', '--platform', $Platform, $ref
        ) -Context "pull $ref"

        # ---- 4. Assert we actually got arm64, not a silent host-arch pull --
        $gotArch = (docker image inspect $ref --format '{{.Architecture}}' 2>$null | Select-Object -First 1)
        $wantArch = ($Platform -split '/')[1]
        if ($gotArch -and $gotArch -ne $wantArch) {
            throw @"
Architecture mismatch for $ref
  requested: $wantArch
  local store reports: $gotArch
This is the containerd image store problem. Enable:
  Docker Desktop > Settings > General > 'Use containerd for pulling and storing images'
then re-run with -Force. Loading this tar on the Spark would fail with 'exec format error'.
"@
        }
        Write-Log OK "Local image architecture confirmed: $gotArch"

        # ---- 5. Save ------------------------------------------------------
        Invoke-Native -FilePath 'docker' -Arguments @(
            'save', '-o', $tarPath, $ref
        ) -Context "save $ref"
    }

    $sizeGB = [math]::Round((Get-Item -LiteralPath $tarPath).Length / 1GB, 2)
    $sha    = Get-Sha256 -Path $tarPath
    Write-Log OK "$alias -> $tarPath (${sizeGB} GB)"

    Add-ManifestEntry -Manifest $Manifest -Category 'images' -Entry @{
        alias     = $alias
        ref       = $ref
        platform  = $Platform
        digest    = $digest
        tar       = "images/$alias.tar"
        size_gb   = $sizeGB
        sha256    = $sha
        pulled_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Invoke-ImageStage {
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][hashtable]$Manifest,
        [switch]$Force
    )
    Write-Log STEP '=== STAGE: CONTAINER IMAGES ==='
    Assert-DockerReady
    Assert-FreeSpace -Path $WorkRoot -RequiredGB 40

    $imagesRoot = New-StagingDirectory -Path (Join-Path $WorkRoot 'images')
    foreach ($img in $Config.Images) {
        Get-ContainerImage -Image $img -Platform $Config.TargetPlatform `
                           -ImagesRoot $imagesRoot -Manifest $Manifest -Force:$Force
    }
    Write-Log OK 'All container images staged.'
}
