<#
.SYNOPSIS
    Shared helpers for SPARKSOC staging.
#>

$script:LogFile = $null

function Initialize-StagingLog {
    param([Parameter(Mandatory)][string]$WorkRoot)
    $logDir = Join-Path $WorkRoot 'logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $script:LogFile = Join-Path $logDir ("staging-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
    Write-Log INFO "Staging log: $script:LogFile"
}

function Write-Log {
    param(
        [ValidateSet('INFO','WARN','ERROR','OK','STEP')][string]$Level = 'INFO',
        [Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Message
    )
    $text  = $Message -join ' '
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = "[$stamp] [$Level] $text"
    $color = switch ($Level) {
        'ERROR' { 'Red' }; 'WARN' { 'Yellow' }; 'OK' { 'Green' }
        'STEP'  { 'Cyan' }; default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding utf8 }
}

function Assert-Command {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$InstallHint = ''
    )
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Log ERROR "Required command '$Name' not found on PATH."
        if ($InstallHint) { Write-Log ERROR "  Install: $InstallHint" }
        throw "Missing prerequisite: $Name"
    }
    Write-Log OK "Found $Name -> $($cmd.Source)"
}

function Get-FreeSpaceGB {
    param([Parameter(Mandatory)][string]$Path)
    $root = [System.IO.Path]::GetPathRoot((Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue) ?? $Path)
    if (-not $root) { return -1 }
    $drive = Get-PSDrive -Name $root.TrimEnd(':\') -ErrorAction SilentlyContinue
    if (-not $drive) { return -1 }
    return [math]::Round($drive.Free / 1GB, 1)
}

function Assert-FreeSpace {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$RequiredGB
    )
    $free = Get-FreeSpaceGB -Path $Path
    if ($free -lt 0) {
        Write-Log WARN "Could not determine free space for $Path — continuing."
        return
    }
    if ($free -lt $RequiredGB) {
        throw "Insufficient space on $Path : ${free} GB free, ${RequiredGB} GB required."
    }
    Write-Log OK "Space check $Path : ${free} GB free (need ${RequiredGB} GB)."
}

function Test-UsbFileSystem {
    <#  FAT32 cannot store files >4 GB. Refuse early rather than at 90%. #>
    param([Parameter(Mandatory)][string]$UsbRoot)
    $letter = ([System.IO.Path]::GetPathRoot($UsbRoot)).TrimEnd('\').TrimEnd(':')
    if (-not $letter) { Write-Log WARN "Cannot parse drive letter from $UsbRoot"; return }
    try {
        $vol = Get-Volume -DriveLetter $letter -ErrorAction Stop
        Write-Log INFO "USB volume $($letter): filesystem = $($vol.FileSystem)"
        if ($vol.FileSystem -eq 'FAT32') {
            throw "USB target is FAT32. Reformat as exFAT or NTFS — model shards exceed 4 GB."
        }
        Write-Log OK "USB filesystem $($vol.FileSystem) is acceptable."
    } catch [System.Management.Automation.ItemNotFoundException] {
        Write-Log WARN "USB volume $letter not present yet. Insert media before the Bundle stage."
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Invoke-Native {
    <#
    .SYNOPSIS
        Run an external command, stream output, throw on non-zero exit.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowFailure,
        [string]$Context = ''
    )
    $display = "$FilePath $($Arguments -join ' ')"
    Write-Log INFO "exec: $display"
    & $FilePath @Arguments 2>&1 | ForEach-Object {
        $line = $_.ToString()
        Write-Host "    $line" -ForegroundColor DarkGray
        if ($script:LogFile) { Add-Content -Path $script:LogFile -Value "    $line" -Encoding utf8 }
    }
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowFailure) {
        throw "Command failed (exit $code)$(if($Context){" during $Context"}): $display"
    }
    return $code
}

function New-StagingDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
        Write-Log INFO "Created $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Add-ManifestEntry {
    <#
    .SYNOPSIS
        Append an artifact record to the in-memory manifest.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Manifest,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][hashtable]$Entry
    )
    if (-not $Manifest.ContainsKey($Category)) { $Manifest[$Category] = @() }
    $Manifest[$Category] += $Entry
}
