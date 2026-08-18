# 06 — Splunk SOAR integration

Assets, credentials, the automation user, and the custom scripts the allowlist
references.

---

## 1. What the harness uses SOAR for

| Purpose | Endpoint | When |
|---|---|---|
| Create the case container | `POST /rest/container` | immediately after triage |
| Attach observables | `POST /rest/artifact` | with the container |
| Narrative and approval tasks | `POST /rest/note` | after deep analysis, and per approval |
| Dispatch an action | `POST /rest/action_run` | evidence collection, approved containment |
| Poll dispatch status | `GET /rest/action_run/{id}` | |
| Retrieve action output | `GET /rest/app_run?_filter_action_run={id}` | feeds the next reasoning turn |
| Update severity/fields | `POST /rest/container/{id}` | when the deep verdict lands |

The harness does **not** trigger playbooks. Containers are created with
`run_automation: false` so SOAR playbooks and the harness do not both act on the
same case. If you want a playbook to run afterwards, trigger it on the
`sparksoc` tag rather than on container creation.

---

## 2. Automation user and token

1. **Administration → User Management → Users → + User**
2. Type: **Automation**
3. Username: `sparksoc_automation`
4. Role: `sparksoc_automation` (created in §3)
5. Allowed IPs: the management VM only
6. Save, then reopen the user and copy the **REST API key**

```bash
printf '%s' 'PASTE_TOKEN' > /opt/sparksoc/code/harness/secrets/soar_token
chmod 400 /opt/sparksoc/code/harness/secrets/soar_token
```

Test:

```bash
curl -sk -H "ph-auth-token: $(cat secrets/soar_token)" \
  https://10.90.1.20/rest/version | python3 -m json.tool
```

---

## 3. Role

**Administration → User Management → Roles → + Role**, name `sparksoc_automation`.

| Permission | Setting | Why |
|---|---|---|
| Containers: View, Edit, Add | yes | create and update cases |
| Artifacts: View, Add | yes | attach observables |
| Notes: View, Add | yes | narrative and approval tasks |
| Playbooks: View | yes | read-only |
| Playbooks: Execute | **no** | the harness orchestrates; it must not also fire playbooks |
| Assets: View | yes | resolve asset names |
| Assets: Edit | **no** | |
| System Settings | **no** | |
| Users | **no** | |

Scope the role to the asset group containing only range assets. A token that
leaks from the harness should not reach production infrastructure, and role
scoping is the control that guarantees it — not the allowlist, which only
constrains this application.

---

## 4. WinRM asset

**Apps → Windows Remote Management → Configure New Asset**

| Field | Value |
|---|---|
| Asset name | `range_winrm` — must match `common/action_allowlist.yaml` exactly |
| Product vendor | Microsoft |
| IP/Hostname | leave blank; supplied per action |
| Verify server certificate | true (see §4.2) |
| Username | `RANGE\svc_soar_collect` |
| Password | the service account password |
| Protocol | https |
| Port | 5986 |
| Transport | ntlm or kerberos |
| Default protocol | https |

### 4.1 Service account

Create `svc_soar_collect` in the range domain with the **minimum** rights for
read-only collection:

```powershell
# On each range Windows target, or via GPO
$acct = "RANGE\svc_soar_collect"

# WinRM access
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI

# Read event logs without full admin
Add-LocalGroupMember -Group "Event Log Readers"        -Member $acct
Add-LocalGroupMember -Group "Performance Log Users"    -Member $acct
Add-LocalGroupMember -Group "Remote Management Users"  -Member $acct
```

Note honestly: process listing with command lines, and any of the containment
actions, need more than this. Two options:

- **Two assets.** `range_winrm` with the low-privilege account for COLLECT, and
  a separate `range_winrm_admin` for CONTAIN. Update the allowlist's `assets`
  block. More setup, much smaller blast radius on token compromise.
- **One admin account** scoped to range hosts only, never a domain admin.

The two-asset split is the better answer, and the allowlist already supports it —
`contain_*` actions just need `asset: winrm_range_admin` and a matching entry.

### 4.2 HTTPS listener

```powershell
# On each range Windows target
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME `
          -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
         -CertificateThumbPrint $cert.Thumbprint -Force
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound `
                    -LocalPort 5986 -Protocol TCP -Action Allow `
                    -RemoteAddress 10.90.1.20
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
```

Import each certificate into SOAR (**Administration → Certificates**) so
certificate verification can stay on. Turning verification off on a range you are
using to evaluate detection quality undermines the exercise.

Test from SOAR: **Assets → range_winrm → Test Connectivity**.

---

## 5. SSH asset

**Apps → SSH → Configure New Asset**

| Field | Value |
|---|---|
| Asset name | `range_ssh` |
| Username | `svc_soar_collect` |
| RSA key | paste the private key, or use password auth |
| Root privilege escalation | as required per §5.1 |
| Port | 22 |

### 5.1 Least privilege on RHEL

```bash
# On each RHEL range target
useradd -m -s /bin/bash svc_soar_collect
mkdir -p /home/svc_soar_collect/.ssh
cat > /home/svc_soar_collect/.ssh/authorized_keys <<'KEY'
ssh-rsa AAAA... soar@range
KEY
chown -R svc_soar_collect: /home/svc_soar_collect/.ssh
chmod 700 /home/svc_soar_collect/.ssh
chmod 600 /home/svc_soar_collect/.ssh/authorized_keys

# Only the specific read-only commands the allowlist can invoke
cat > /etc/sudoers.d/sparksoc <<'SUDO'
Cmnd_Alias SPARKSOC_COLLECT = \
    /usr/bin/ps -eo pid\,ppid\,user\,lstart\,cmd --sort=start_time, \
    /usr/bin/ss -tunap, \
    /usr/bin/systemctl list-units --type=service --all, \
    /usr/bin/crontab -l -u *, \
    /usr/bin/cat /etc/crontab, \
    /usr/bin/find /etc/cron.d -type f, \
    /usr/bin/cat /etc/rc.local, \
    /usr/bin/find /home -name authorized_keys

svc_soar_collect ALL=(root) NOPASSWD: SPARKSOC_COLLECT
SUDO
chmod 440 /etc/sudoers.d/sparksoc
visudo -c
```

Note what this achieves: even if the harness, the model, and the SOAR token were
all fully compromised, the SSH path can run exactly these commands. That is a
stronger guarantee than any allowlist in application code.

---

## 6. Splunk asset

**Apps → Splunk → Configure New Asset**, name `splunk_enterprise`, pointing at
the search head with a **read-only** Splunk account.

The `correlate_splunk_history` action lets the model choose a saved search **by
name from an enum** — it cannot compose SPL. Letting a language model write SPL
against a production Splunk instance is a remote code execution surface, which is
why the allowlist encodes the search names rather than a query parameter.

The five baseline searches are at the bottom of
`splunk/savedsearches.example.conf`. Install them, or the action returns nothing.

---

## 7. Custom scripts

Three allowlist actions reference scripts by `script_ref` or `command_ref`. Add
them to SOAR under **Administration → Automation → Scripts** (or as a small
custom app), then confirm the "run script" action can invoke them by name.

### Get-ProcessTree (WinRM)

```powershell
param([Parameter(Mandatory=$true)][int]$Pid)

function Get-Ancestry {
    param([int]$ProcessId, [int]$Depth = 0)
    if ($Depth -gt 12) { return }
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
    if (-not $p) { return }

    $sig = $null
    if ($p.ExecutablePath -and (Test-Path $p.ExecutablePath)) {
        $sig = Get-AuthenticodeSignature $p.ExecutablePath -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        Depth        = $Depth
        ProcessId    = $p.ProcessId
        ParentPid    = $p.ParentProcessId
        Name         = $p.Name
        Path         = $p.ExecutablePath
        CommandLine  = $p.CommandLine
        CreationDate = $p.CreationDate
        Owner        = (Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue).User
        SignatureStatus = if ($sig) { $sig.Status.ToString() } else { 'Unknown' }
        Signer          = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
    }

    if ($p.ParentProcessId -gt 4) { Get-Ancestry -ProcessId $p.ParentProcessId -Depth ($Depth + 1) }
}

$tree = @(Get-Ancestry -ProcessId $Pid)
$children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$Pid" |
    Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate

[pscustomobject]@{ Ancestry = $tree; Children = $children } | ConvertTo-Json -Depth 6
```

### Get-PersistenceArtifacts (WinRM)

```powershell
$out = [ordered]@{}

$out.ScheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' } |
    ForEach-Object {
        $i = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        [pscustomobject]@{
            TaskName = $_.TaskName; TaskPath = $_.TaskPath; State = "$($_.State)"
            Author   = $_.Author
            Actions  = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
            RunAs    = $_.Principal.UserId
            LastRun  = $i.LastRunTime; NextRun = $i.NextRunTime
        }
    }

$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$out.RunKeys = foreach ($k in $runKeys) {
    if (Test-Path $k) {
        (Get-ItemProperty $k).PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Value = $_.Value } }
    }
}

$out.Services = Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -and $_.PathName -notlike '*\Windows\System32\svchost.exe*' } |
    Select-Object Name, DisplayName, PathName, StartMode, State, StartName

$out.WmiSubscriptions = @{
    Filters   = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
                Select-Object Name, Query
    Consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
                Select-Object Name, __CLASS
    Bindings  = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                Select-Object Filter, Consumer
}

$startup = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
             "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")
$out.StartupFolder = foreach ($p in $startup) {
    if (Test-Path $p) { Get-ChildItem $p -Force | Select-Object FullName, Length, LastWriteTime }
}

[pscustomobject]$out | ConvertTo-Json -Depth 6 -Compress
```

### GetLinuxPersistence (SSH)

```bash
#!/usr/bin/env bash
echo "=== crontabs (per user) ==="
for u in $(cut -f1 -d: /etc/passwd); do
  c=$(sudo crontab -l -u "$u" 2>/dev/null) && [ -n "$c" ] && echo "--- $u ---" && echo "$c"
done

echo; echo "=== /etc/crontab and /etc/cron.d ==="
sudo cat /etc/crontab 2>/dev/null
for f in $(sudo find /etc/cron.d -type f 2>/dev/null); do echo "--- $f ---"; sudo cat "$f"; done

echo; echo "=== systemd services (non-vendor) ==="
sudo systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | head -100

echo; echo "=== recently modified unit files ==="
find /etc/systemd/system /usr/lib/systemd/system -name '*.service' -mtime -30 2>/dev/null

echo; echo "=== rc.local ==="
sudo cat /etc/rc.local 2>/dev/null || echo "(absent)"

echo; echo "=== authorized_keys ==="
for f in $(sudo find /root /home -name authorized_keys 2>/dev/null); do
  echo "--- $f (modified $(stat -c %y "$f" 2>/dev/null)) ---"; sudo cat "$f"
done

echo; echo "=== shell profiles modified in the last 30 days ==="
find /etc/profile.d /root /home -maxdepth 2 \
     \( -name '.bashrc' -o -name '.bash_profile' -o -name '*.sh' \) \
     -mtime -30 2>/dev/null

echo; echo "=== setuid binaries outside standard paths ==="
sudo find / -perm -4000 -type f 2>/dev/null | grep -vE '^/(usr/bin|usr/sbin|bin|sbin)/'
```

### KillProcess (SSH, CONTAIN tier)

```bash
#!/usr/bin/env bash
# Invoked only after human approval. Refuses PIDs that are not a running,
# non-system process, so an approved action cannot be turned into a host kill.
set -euo pipefail
PID="${1:?usage: KillProcess <pid>}"
[[ "$PID" =~ ^[0-9]{1,7}$ ]] || { echo "invalid pid"; exit 1; }
(( PID > 100 )) || { echo "refusing to signal a system pid"; exit 1; }

echo "--- pre-kill state ---"
ps -p "$PID" -o pid,ppid,user,lstart,cmd || { echo "pid $PID not running"; exit 1; }

sudo kill -TERM "$PID"; sleep 3
if ps -p "$PID" >/dev/null 2>&1; then
  echo "SIGTERM ignored; escalating to SIGKILL"; sudo kill -KILL "$PID"; sleep 1
fi
ps -p "$PID" >/dev/null 2>&1 && { echo "FAILED: pid $PID still running"; exit 1; }
echo "pid $PID terminated"
```

Add `/usr/bin/kill` to the sudoers alias in §5.1 if you enable this action.

Register these command strings under the names used in the allowlist
(`GetLinuxPersistence`, `KillProcess`) so the SSH app's "execute program" action
can invoke them. Do not let the model supply the command string.

---

## 8. Align the allowlist

`common/action_allowlist.yaml` must match reality. The three things to check:

```yaml
assets:
  winrm_range:
    soar_asset: "range_winrm"     # exactly the SOAR asset name
  ssh_range:
    soar_asset: "range_ssh"
  splunk_search:
    soar_asset: "splunk_enterprise"

scope:
  range_cidrs:
    - "10.90.10.0/24"             # your actual range subnets
    - "10.90.11.0/24"
    - "10.90.12.0/24"
  hostname_pattern: "^(WS2022|WIN11|RHEL)-RANGE-[0-9]{2}$"   # your naming
```

Action names must match SOAR's exactly — `list processes`, not `List Processes`.
Confirm against the app's documentation:

```bash
curl -sk -H "ph-auth-token: $TOKEN" \
  "https://10.90.1.20/rest/app?_filter_name__icontains=\"windows remote\"" \
  | python3 -m json.tool
```

After editing, restart the harness. It self-tests the allowlist at startup and
refuses to run if it is inconsistent.

---

## 9. Verify

```bash
cd /opt/sparksoc/code/validate
python3 e2e_test.py --config config.yaml --only security
```

Then a real dispatch, in dry-run first:

```bash
curl -s http://127.0.0.1:8080/v1/cases?limit=1 | python3 -m json.tool
# find a case, then inspect what it would have done
curl -s http://127.0.0.1:8080/v1/case/<CASE_ID>/audit \
  | python3 -c '
import sys, json
for e in json.load(sys.stdin)["entries"]:
    if e["event"].startswith("action."):
        print(e["event"], e["detail"])'
```

---

## 10. Approvals

Containment never auto-dispatches. When the model recommends one, the harness:

1. validates it against the allowlist and the range scope
2. checks confidence against `require_confidence` (0.75 for CONTAIN)
3. creates a pending approval with a timeout (60 minutes default)
4. writes a **task note** on the SOAR container with the prompt, the warning, the
   model's justification, and the approval id
5. audits `approval.requested`

To act on it:

```bash
curl -s http://127.0.0.1:8080/v1/approvals | python3 -m json.tool

curl -XPOST http://127.0.0.1:8080/v1/approval/APR-A1B2C3D4-02 \
  -H 'Content-Type: application/json' \
  -d '{"decision":"approve","approver":"k.eade","note":"confirmed real, not exercise"}'
```

On a purple-team range, most containment approvals should be **denied** — the
warning text on `contain_isolate_host` says so explicitly, because isolating a
host ends the exercise on it. The value of the recommendation is that it tells
you what a real SOC would have done, and the report scores it.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| container creation 400 | bad label | `SOAR_LABEL` must be an existing SOAR label |
| duplicate containers per incident | `source_data_identifier` changing | harness uses `sparksoc:<fingerprint>`; check that Splunk emits stable host/user fields |
| action_run 400 "asset not found" | name mismatch | allowlist `soar_asset` vs. SOAR asset name, exactly |
| action_run 400 "action not found" | name mismatch | exact SOAR action name, lowercase |
| every action times out | asset connectivity | SOAR → Asset → Test Connectivity |
| WinRM "access denied" | insufficient rights | §4.1; some actions need more than Event Log Readers |
| SSH "sudo: a password is required" | sudoers not applied | `visudo -c`; command string must match the alias exactly |
| TLS verification errors | CA not imported | Administration → Certificates, or pin the CA in `SOAR_CA_BUNDLE` |
| harness logs "SOAR unavailable" | outage | calls journal to `state/soar_retry.jsonl`; `POST /v1/soar/replay` after recovery |

---

## 12. Next

[`07-VALIDATION.md`](07-VALIDATION.md)
