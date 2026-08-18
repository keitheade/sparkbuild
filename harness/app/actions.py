"""Action allowlist enforcement — the security boundary between model and range.

Nothing a model produces reaches SOAR without passing through `validate()`.
The checks, in order, and why each exists:

  1. action_id must exist in the allowlist          — model cannot invent actions
  2. tier must permit dispatch                      — CONTAIN needs a human
  3. every required parameter present               — no partially-formed dispatch
  4. no unexpected parameters                       — no smuggling extra fields
  5. each value matches its declared validator      — no injection through a value
  6. target resolves inside scope.range_cidrs and   — cannot touch production
     is not in never_target, hostname matches
     scope.hostname_pattern
  7. per-case action budget not exhausted           — bounds a runaway loop

Failures are recorded, not sanitised. A parameter that does not validate causes
the whole action to be rejected. Repairing attacker-influenced input is how
these systems get owned.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

LOG = logging.getLogger("sparksoc.actions")


@dataclass
class ValidationResult:
    allowed: bool
    tier: str = ""
    reason: str = ""
    soar_action: str = ""
    soar_asset: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    approval_prompt: str = ""
    approval_warning: str = ""
    approval_roles: list[str] = field(default_factory=list)


class ActionAllowlist:
    def __init__(self, path: Path, force_dry_run: bool = False):
        self.path = path
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))

        self.version = raw.get("version", 0)
        self.scope = raw.get("scope", {}) or {}
        self.assets = raw.get("assets", {}) or {}
        self.validators = raw.get("validators", {}) or {}
        self.policy = raw.get("policy", {}) or {}
        self.actions: dict[str, dict[str, Any]] = {
            a["id"]: a for a in raw.get("actions", []) if a.get("id")
        }

        self.dry_run = bool(force_dry_run or self.policy.get("dry_run", False))

        self._range_networks = []
        for cidr in self.scope.get("range_cidrs", []):
            try:
                self._range_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                LOG.error("Invalid CIDR in allowlist scope.range_cidrs: %r", cidr)

        self._never = set(self.scope.get("never_target", []))
        pat = self.scope.get("hostname_pattern")
        self._hostname_re = re.compile(pat) if pat else None

        self._compiled: dict[str, re.Pattern[str]] = {}
        for name, spec in self.validators.items():
            if isinstance(spec, dict) and spec.get("pattern"):
                try:
                    self._compiled[name] = re.compile(spec["pattern"])
                except re.error as exc:
                    LOG.error("Invalid regex for validator %r: %s", name, exc)

        LOG.info("Loaded action allowlist v%s: %d actions (%d COLLECT, %d CONTAIN, %d DENY), dry_run=%s",
                 self.version, len(self.actions),
                 sum(1 for a in self.actions.values() if a.get("tier") == "COLLECT"),
                 sum(1 for a in self.actions.values() if a.get("tier") == "CONTAIN"),
                 sum(1 for a in self.actions.values() if a.get("tier") == "DENY"),
                 self.dry_run)

    # ------------------------------------------------------------------
    # Catalogue exposed to the model
    # ------------------------------------------------------------------
    def collect_action_ids(self) -> list[str]:
        return [k for k, v in self.actions.items() if v.get("tier") == "COLLECT"]

    def all_proposable_ids(self) -> list[str]:
        """Ids the model may name. DENY actions are included deliberately so an
        attempt to reach one is recorded rather than silently unparseable."""
        return list(self.actions.keys())

    def catalogue_text(self, tiers: tuple[str, ...] = ("COLLECT",)) -> str:
        """Human-readable catalogue injected into the reasoning prompt."""
        lines: list[str] = []
        for aid, a in self.actions.items():
            if a.get("tier") not in tiers:
                continue
            params = a.get("parameters", {}) or {}
            param_desc = []
            for pname, pspec in params.items():
                if pspec.get("from") == "target_host":
                    param_desc.append(f"{pname} (the target hostname)")
                elif "enum" in pspec:
                    opts = "|".join(str(x) for x in pspec["enum"])
                    param_desc.append(f"{pname} (one of: {opts})")
                else:
                    req = "required" if pspec.get("required") else "optional"
                    param_desc.append(f"{pname} ({pspec.get('validator','string')}, {req})")
            lines.append(
                f"- {aid} [{a.get('tier')}]\n"
                f"    {a.get('description','')}\n"
                f"    use when: {a.get('when','')}\n"
                f"    parameters: {'; '.join(param_desc) or 'none'}"
            )
        return "\n".join(lines) if lines else "(no actions available)"

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------
    def target_in_scope(self, target: str) -> tuple[bool, str]:
        if not target:
            return False, "empty target"
        if target in self._never:
            return False, f"{target} is in scope.never_target"

        # IP literal
        try:
            addr = ipaddress.ip_address(target)
            for net in self._range_networks:
                if addr in net:
                    return True, ""
            return False, f"{target} is outside every configured range CIDR"
        except ValueError:
            pass

        # Hostname
        if self._hostname_re and not self._hostname_re.match(target):
            return False, (f"hostname {target!r} does not match "
                           f"scope.hostname_pattern {self._hostname_re.pattern!r}")

        # If the name resolves, the address must also be in range. In an airgap
        # with no DNS this resolution simply fails, and the pattern match above
        # is what governs — which is the intended posture.
        try:
            resolved = socket.gethostbyname(target)
            addr = ipaddress.ip_address(resolved)
            if not any(addr in net for net in self._range_networks):
                return False, f"{target} resolves to {resolved}, outside the range CIDRs"
        except (OSError, ValueError):
            pass

        return True, ""

    # ------------------------------------------------------------------
    # Parameter validation
    # ------------------------------------------------------------------
    def _validate_value(self, validator_name: str, value: str) -> tuple[bool, str]:
        spec = self.validators.get(validator_name)
        if spec is None:
            return False, f"unknown validator {validator_name!r}"

        if "enum" in spec:
            if value not in spec["enum"]:
                return False, f"value not in permitted enum for {validator_name}"
            return True, ""

        max_len = spec.get("max_length")
        if max_len and len(value) > max_len:
            return False, f"value exceeds max_length {max_len} for {validator_name}"

        rx = self._compiled.get(validator_name)
        if rx is None:
            return False, f"validator {validator_name!r} has no usable pattern"
        if not rx.match(value):
            return False, f"value does not match {validator_name} pattern"

        max_int = spec.get("max_int")
        if max_int is not None:
            try:
                if int(value) > max_int:
                    return False, f"value exceeds max_int {max_int}"
            except ValueError:
                return False, "value is not an integer"

        return True, ""

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def validate(
        self,
        action_id: str,
        parameters: dict[str, Any],
        *,
        target_host: str | None = None,
        confidence: float = 0.0,
        actions_taken_this_case: int = 0,
    ) -> ValidationResult:

        action = self.actions.get(action_id)
        if action is None:
            return ValidationResult(False, reason=f"action_id {action_id!r} is not in the allowlist")

        tier = action.get("tier", "DENY")

        # --- DENY -------------------------------------------------------
        if tier == "DENY":
            return ValidationResult(
                False, tier=tier,
                reason=f"action is DENY tier: {action.get('reason', 'not permitted from this pipeline')}",
            )

        tier_policy = (self.policy.get("tiers", {}) or {}).get(tier, {}) or {}

        # --- budget -----------------------------------------------------
        max_per_case = tier_policy.get("max_per_case")
        if max_per_case is not None and actions_taken_this_case >= max_per_case:
            return ValidationResult(
                False, tier=tier,
                reason=f"per-case {tier} budget of {max_per_case} already exhausted",
            )

        # --- confidence -------------------------------------------------
        required_conf = float(tier_policy.get("require_confidence", 0.0))
        if confidence < required_conf:
            return ValidationResult(
                False, tier=tier,
                reason=f"confidence {confidence:.2f} below {tier} threshold {required_conf:.2f}",
            )

        # --- parameters -------------------------------------------------
        spec_params: dict[str, Any] = action.get("parameters", {}) or {}
        resolved: dict[str, Any] = {}

        unexpected = set(parameters) - set(spec_params)
        if unexpected:
            return ValidationResult(
                False, tier=tier,
                reason=f"unexpected parameter(s): {', '.join(sorted(unexpected))}",
            )

        effective_target = target_host

        for pname, pspec in spec_params.items():
            value = parameters.get(pname)

            # Parameters marked `from: target_host` are filled by the harness
            # from the extracted alert entity, never by the model.
            if pspec.get("from") == "target_host":
                value = target_host or value

            if value is None and "default" in pspec:
                value = pspec["default"]

            if value is None or value == "":
                if pspec.get("required", False):
                    return ValidationResult(False, tier=tier,
                                            reason=f"missing required parameter {pname!r}")
                continue

            value = str(value)

            if "enum" in pspec:
                if value not in pspec["enum"]:
                    return ValidationResult(
                        False, tier=tier,
                        reason=f"parameter {pname!r} value not in permitted enum",
                    )
            else:
                vname = pspec.get("validator")
                if not vname:
                    return ValidationResult(False, tier=tier,
                                            reason=f"parameter {pname!r} has no validator declared")
                ok, why = self._validate_value(vname, value)
                if not ok:
                    return ValidationResult(False, tier=tier,
                                            reason=f"parameter {pname!r}: {why}")

            if pspec.get("from") == "target_host":
                effective_target = value

            resolved[pname] = value

        # --- scope ------------------------------------------------------
        if effective_target:
            in_scope, why = self.target_in_scope(effective_target)
            if not in_scope:
                return ValidationResult(
                    False, tier=tier,
                    reason=f"target out of scope: {why}",
                )
        elif tier in {"COLLECT", "CONTAIN"} and any(
            p.get("from") == "target_host" for p in spec_params.values()
        ):
            return ValidationResult(False, tier=tier,
                                    reason="no target host could be resolved for this action")

        # --- asset ------------------------------------------------------
        asset_key = action.get("asset")
        asset = self.assets.get(asset_key, {}) if asset_key else {}
        if asset_key and not asset:
            return ValidationResult(False, tier=tier,
                                    reason=f"asset {asset_key!r} referenced but not defined in allowlist")

        approval = action.get("approval", {}) or {}
        requires_approval = not bool(tier_policy.get("auto_dispatch", False))

        prompt = approval.get("prompt", f"Approve {action_id}?")
        try:
            prompt = prompt.format(target_host=effective_target or "?", **resolved)
        except (KeyError, IndexError):
            pass

        return ValidationResult(
            allowed=True,
            tier=tier,
            soar_action=action.get("soar_action", ""),
            soar_asset=asset.get("soar_asset", ""),
            parameters=resolved,
            requires_approval=requires_approval,
            approval_prompt=prompt,
            approval_warning=approval.get("warning", ""),
            approval_roles=approval.get("roles", []),
        )

    # ------------------------------------------------------------------
    def self_test(self) -> list[str]:
        """Consistency checks run at startup. Returns a list of problems."""
        problems: list[str] = []

        if not self._range_networks:
            problems.append("scope.range_cidrs is empty — no target would ever validate")

        for aid, a in self.actions.items():
            tier = a.get("tier")
            if tier not in {"COLLECT", "CONTAIN", "DENY"}:
                problems.append(f"{aid}: unknown tier {tier!r}")
                continue
            if tier == "DENY":
                continue

            if a.get("asset") and a["asset"] not in self.assets:
                problems.append(f"{aid}: references undefined asset {a['asset']!r}")
            if not a.get("soar_action"):
                problems.append(f"{aid}: no soar_action defined")

            for pname, pspec in (a.get("parameters") or {}).items():
                if "enum" in pspec:
                    continue
                v = pspec.get("validator")
                if not v:
                    problems.append(f"{aid}.{pname}: no validator")
                elif v not in self.validators:
                    problems.append(f"{aid}.{pname}: undefined validator {v!r}")

            if tier == "CONTAIN" and not a.get("approval"):
                problems.append(f"{aid}: CONTAIN tier with no approval block")

        collect_policy = (self.policy.get("tiers", {}) or {}).get("COLLECT", {})
        contain_policy = (self.policy.get("tiers", {}) or {}).get("CONTAIN", {})
        if contain_policy.get("auto_dispatch"):
            problems.append(
                "policy.tiers.CONTAIN.auto_dispatch is true — containment would fire without "
                "human approval. This contradicts the deployed tiering decision."
            )
        if not collect_policy:
            problems.append("policy.tiers.COLLECT is missing")

        return problems
