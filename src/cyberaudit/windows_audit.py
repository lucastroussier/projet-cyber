from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import Finding, SoftwareRecord


WINDOWS_COLLECTION_SCRIPT = r"""
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue |
  Select-Object CSName, Caption, Version, BuildNumber, LastBootUpTime, OSArchitecture
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue |
  Select-Object Manufacturer, Model, Domain, PartOfDomain, Workgroup, TotalPhysicalMemory
$hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue |
  Select-Object HotFixID, InstalledOn, Description)
$firewalls = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue |
  Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
  $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue |
    Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, AntispywareSignatureAge, QuickScanAge, FullScanAge
} else {
  $defender = [PSCustomObject]@{ available = $false }
}
$rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
$smb = $null
if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
  $smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
}
$security = [PSCustomObject]@{
  rdpEnabled = [bool]($rdp -and $rdp.fDenyTSConnections -eq 0)
  uacEnabled = [bool]($uac -and $uac.EnableLUA -eq 1)
  smb1State = if ($smb) { [string]$smb.State } else { 'Unknown' }
}
$bitlocker = @()
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
  $bitlocker = @(Get-BitLockerVolume -ErrorAction SilentlyContinue |
    Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod, LockStatus)
}
$localAdmins = @()
if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
  try {
    $adminSid = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
    $adminGroup = $adminSid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    $localAdmins = @(Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop |
      Select-Object Name, ObjectClass, PrincipalSource)
  } catch {
    $localAdmins = @([PSCustomObject]@{ error = $_.Exception.Message })
  }
}
$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.State -eq 'Running' -or $_.StartMode -eq 'Auto' } |
  Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
  Sort-Object DisplayName |
  Select-Object -First 200)
$shares = @()
if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
  $shares = @(Get-SmbShare -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '^[A-Za-z]\$$' -and $_.Name -notin @('ADMIN$', 'IPC$', 'print$') } |
    Select-Object Name, Path, Description, ShareState, FolderEnumerationMode, EncryptData)
}
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$software = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
  Sort-Object DisplayName -Unique)
[PSCustomObject]@{
  system_profile = [PSCustomObject]@{
    os = $os
    hardware = $computer
  }
  hotfixes = $hotfixes
  firewall_profiles = $firewalls
  defender = $defender
  security = $security
  bitlocker = $bitlocker
  local_admins = $localAdmins
  services = $services
  shares = $shares
  software_inventory = $software
}
"""


@dataclass(slots=True)
class WindowsAuditResult:
    findings: list[Finding]
    software_inventory: list[SoftwareRecord]
    metadata: dict[str, Any]


class WindowsLocalAuditor:
    def is_supported(self) -> bool:
        return platform.system().lower() == "windows"

    def run(self) -> WindowsAuditResult:
        if not self.is_supported():
            return WindowsAuditResult(findings=[], software_inventory=[], metadata={"warning": "Audit Windows indisponible hors Windows."})

        payload = self._run_ps_json(f"& {{\n{WINDOWS_COLLECTION_SCRIPT}\n}} | ConvertTo-Json -Depth 8")
        return self._result_from_payload(payload, target=None, source="local")

    def _result_from_payload(self, payload: Any, target: str | None, source: str) -> WindowsAuditResult:
        if not isinstance(payload, dict):
            return self._failure_result(target or "localhost", "La collecte Windows n'a pas retourne de donnees JSON exploitables.", source)
        if payload.get("error"):
            return self._failure_result(target or "localhost", str(payload.get("error")), source)

        software_inventory = [
            SoftwareRecord(
                name=item.get("DisplayName", "").strip(),
                version=self._clean_text(item.get("DisplayVersion")),
                vendor=self._clean_text(item.get("Publisher")),
                install_date=self._clean_text(item.get("InstallDate")),
                host=target,
            )
            for item in self._ensure_list(payload.get("software_inventory"))
            if item.get("DisplayName")
        ]

        system_profile = payload.get("system_profile") if isinstance(payload.get("system_profile"), dict) else {}
        hotfixes = payload.get("hotfixes")
        firewalls = payload.get("firewall_profiles")
        defender = payload.get("defender") if isinstance(payload.get("defender"), dict) else {}
        security = payload.get("security") if isinstance(payload.get("security"), dict) else {}

        findings = self._build_findings(system_profile, hotfixes, firewalls, defender, security)
        findings.extend(self._build_extended_findings(payload, target))
        for finding in findings:
            finding.source = source

        metadata = dict(payload)
        if target:
            metadata["target"] = target
        metadata["collection_mode"] = source
        return WindowsAuditResult(findings=findings, software_inventory=software_inventory, metadata=metadata)

    def _failure_result(self, target: str, error: str, source: str) -> WindowsAuditResult:
        return WindowsAuditResult(
            findings=[
                Finding(
                    title="Audit Windows impossible",
                    severity="Medium",
                    target=target,
                    category="Collection",
                    description="La collecte Windows n'a pas pu aboutir pour cette machine.",
                    recommendation="Verifier les droits PowerShell locaux, les modules Windows disponibles et relancer l'agent en administrateur si necessaire.",
                    evidence={"error": error},
                    source=source,
                )
            ],
            software_inventory=[],
            metadata={"target": target, "error": error, "collection_mode": source},
        )

    def _build_findings(
        self,
        system_profile: dict[str, Any],
        hotfixes: Any,
        firewalls: Any,
        defender: dict[str, Any],
        security: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []
        host_name = self._host_name(system_profile, None)

        hotfix_items = self._ensure_list(hotfixes)
        if hotfix_items and hotfix_items[0].get("error"):
            findings.append(
                Finding(
                    title="Collecte des correctifs en erreur",
                    severity="Medium",
                    target=host_name,
                    category="Patch Management",
                    description="La liste des correctifs Windows n'a pas pu etre triee ou interpretee correctement.",
                    recommendation="Verifier les droits PowerShell et la qualite des donnees remontees par Get-HotFix.",
                    evidence=hotfix_items[0],
                )
            )
        elif hotfix_items:
            sorted_hotfixes = sorted(
                hotfix_items,
                key=lambda item: self._parse_datetime(item.get("InstalledOn")) or datetime(1970, 1, 1, tzinfo=timezone.utc),
                reverse=True,
            )
            newest = sorted_hotfixes[0]
            install_date = self._parse_datetime(newest.get("InstalledOn"))
            if install_date:
                age_days = (datetime.now(timezone.utc) - install_date).days
                if age_days > 45:
                    findings.append(
                        Finding(
                            title="Correctifs Windows anciens",
                            severity="High",
                            target=host_name,
                            category="Patch Management",
                            description="Le dernier correctif Windows recense remonte a plus de 45 jours.",
                            recommendation="Verifier Windows Update, WSUS ou l'outil de gestion de correctifs puis appliquer les mises a jour de securite recentes.",
                            evidence={"latest_hotfix": newest, "age_days": age_days},
                        )
                    )
        else:
            findings.append(
                Finding(
                    title="Historique de correctifs introuvable",
                    severity="High",
                    target=host_name,
                    category="Patch Management",
                    description="Aucun correctif Windows n'a pu etre recupere.",
                    recommendation="Verifier les droits de collecte et l'etat du service Windows Update.",
                    evidence={},
                )
            )

        for profile in self._ensure_list(firewalls):
            if not self._as_bool(profile.get("Enabled")):
                findings.append(
                    Finding(
                        title=f"Pare-feu desactive ({profile.get('Name')})",
                        severity="High",
                        target=host_name,
                        category="Security Configuration",
                        description=f"Le profil pare-feu {profile.get('Name')} est desactive.",
                        recommendation="Activer le pare-feu Windows Defender pour tous les profils applicables.",
                        evidence=profile,
                    )
                )
            if str(profile.get("DefaultInboundAction", "")).lower() == "allow":
                findings.append(
                    Finding(
                        title=f"Politique entrante permissive ({profile.get('Name')})",
                        severity="Medium",
                        target=host_name,
                        category="Security Configuration",
                        description="La politique entrante par defaut du pare-feu est permissive.",
                        recommendation="Utiliser une politique entrante bloquante par defaut puis declarer uniquement les exceptions necessaires.",
                        evidence=profile,
                    )
                )

        if defender.get("available") is False:
            findings.append(
                Finding(
                    title="Etat antivirus indisponible",
                    severity="Medium",
                    target=host_name,
                    category="Endpoint Protection",
                    description="Le statut Microsoft Defender n'a pas pu etre collecte.",
                    recommendation="Verifier si un antivirus tiers est installe ou si Microsoft Defender est desactive.",
                    evidence=defender,
                )
            )
        else:
            if defender.get("RealTimeProtectionEnabled") is False:
                findings.append(
                    Finding(
                        title="Protection temps reel desactivee",
                        severity="High",
                        target=host_name,
                        category="Endpoint Protection",
                        description="La protection temps reel de l'antivirus est desactivee.",
                        recommendation="Reactiver la protection temps reel ou verifier la politique de securite appliquee.",
                        evidence=defender,
                    )
                )
            sig_age = defender.get("AntivirusSignatureAge")
            if isinstance(sig_age, int) and sig_age > 7:
                findings.append(
                    Finding(
                        title="Signatures antivirus anciennes",
                        severity="Medium",
                        target=host_name,
                        category="Endpoint Protection",
                        description="Les signatures antivirus semblent dater de plus de 7 jours.",
                        recommendation="Forcer une mise a jour des signatures Defender ou du produit antivirus deploye.",
                        evidence={"AntivirusSignatureAge": sig_age},
                    )
                )

        if security.get("smb1State") == "Enabled":
            findings.append(
                Finding(
                    title="SMBv1 active",
                    severity="Critical",
                    target=host_name,
                    category="Security Configuration",
                    description="Le protocole SMBv1 est encore active, ce qui expose des risques eleves.",
                    recommendation="Desactiver SMBv1 et migrer les usages vers SMBv2/v3.",
                    evidence=security,
                )
            )
        if security.get("uacEnabled") is False:
            findings.append(
                Finding(
                    title="UAC desactive",
                    severity="High",
                    target=host_name,
                    category="Security Configuration",
                    description="Le controle de compte utilisateur (UAC) est desactive.",
                    recommendation="Reactiver UAC pour limiter l'execution silencieuse de taches privilegiees.",
                    evidence=security,
                )
            )
        if security.get("rdpEnabled") is True:
            findings.append(
                Finding(
                    title="RDP active",
                    severity="Medium",
                    target=host_name,
                    category="Exposed Administration",
                    description="Le bureau a distance est active sur le poste audite.",
                    recommendation="Restreindre l'acces RDP, utiliser un VPN ou un bastion, puis imposer MFA si possible.",
                    evidence=security,
                )
            )

        return findings

    def _build_extended_findings(self, payload: dict[str, Any], target: str | None) -> list[Finding]:
        findings: list[Finding] = []
        system_profile = payload.get("system_profile") if isinstance(payload.get("system_profile"), dict) else {}
        host_name = self._host_name(system_profile, target)
        hardware = system_profile.get("hardware") if isinstance(system_profile.get("hardware"), dict) else {}

        if hardware and hardware.get("PartOfDomain") is False:
            findings.append(
                Finding(
                    title="Poste hors domaine",
                    severity="Info",
                    target=host_name,
                    category="Asset Governance",
                    description="La machine ne semble pas jointe a un domaine Active Directory.",
                    recommendation="Verifier si cette machine doit etre geree par le domaine, les GPO et les outils de supervision du parc.",
                    evidence={"domain": hardware.get("Domain"), "workgroup": hardware.get("Workgroup")},
                )
            )

        unprotected_volumes = [
            item
            for item in self._ensure_list(payload.get("bitlocker"))
            if not self._bitlocker_protected(item.get("ProtectionStatus"))
        ]
        if unprotected_volumes:
            findings.append(
                Finding(
                    title="Volume BitLocker non protege",
                    severity="High",
                    target=host_name,
                    category="Data Protection",
                    description="Au moins un volume audite ne remonte pas de protection BitLocker active.",
                    recommendation="Activer BitLocker sur les volumes fixes et verifier la sauvegarde des cles de recuperation.",
                    evidence={"volumes": unprotected_volumes[:5]},
                )
            )

        admins = [item for item in self._ensure_list(payload.get("local_admins")) if not item.get("error")]
        broad_admins = [
            item
            for item in admins
            if re.search(r"(domain users|utilisateurs du domaine|everyone|tout le monde)", str(item.get("Name", "")), re.IGNORECASE)
        ]
        if broad_admins:
            findings.append(
                Finding(
                    title="Groupe large dans les administrateurs locaux",
                    severity="High",
                    target=host_name,
                    category="Identity and Access",
                    description="Un groupe large semble membre des administrateurs locaux.",
                    recommendation="Retirer les groupes larges des administrateurs locaux et appliquer un modele de moindre privilege.",
                    evidence={"members": broad_admins[:10]},
                )
            )
        elif len(admins) > 8:
            findings.append(
                Finding(
                    title="Nombre eleve d'administrateurs locaux",
                    severity="Medium",
                    target=host_name,
                    category="Identity and Access",
                    description="Le groupe administrateurs local contient de nombreux membres.",
                    recommendation="Revoir les appartenances locales et limiter les droits administrateur aux comptes et groupes requis.",
                    evidence={"admin_count": len(admins), "members": admins[:12]},
                )
            )

        service_accounts = [
            item
            for item in self._ensure_list(payload.get("services"))
            if self._is_named_service_account(item.get("StartName"))
        ]
        if service_accounts:
            findings.append(
                Finding(
                    title="Services executes avec comptes nominatifs",
                    severity="Medium",
                    target=host_name,
                    category="Identity and Access",
                    description="Des services tournent avec des comptes utilisateurs ou de domaine.",
                    recommendation="Verifier que ces comptes sont geres, non interactifs, avec mot de passe controle et privileges minimaux.",
                    evidence={"services": service_accounts[:10]},
                )
            )

        shares = self._ensure_list(payload.get("shares"))
        if shares:
            findings.append(
                Finding(
                    title="Partages SMB non administratifs detectes",
                    severity="Info",
                    target=host_name,
                    category="Data Exposure",
                    description="Des partages SMB non administratifs sont exposes par la machine.",
                    recommendation="Verifier les permissions NTFS/partage, le besoin metier et l'acces depuis les VLAN non autorises.",
                    evidence={"shares": shares[:15]},
                )
            )

        return findings

    def _run_ps_json(self, script: str, timeout: int = 60) -> Any:
        return self._run_ps_json_with_env(script, timeout=timeout)

    def _run_ps_json_with_env(self, script: str, timeout: int = 60, env: dict[str, str] | None = None) -> Any:
        wrapped_script = (
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::UTF8; "
            "$OutputEncoding = [System.Text.UTF8Encoding]::UTF8; "
            + script
        )
        command = ["powershell", "-NoProfile", "-Command", wrapped_script]
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                env=process_env,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout PowerShell apres {timeout} secondes"}
        except (OSError, subprocess.SubprocessError) as exc:
            return {"error": str(exc)}

        if result.returncode != 0:
            return {"error": result.stderr.strip() or result.stdout.strip()}

        stdout = result.stdout.strip()
        if not stdout:
            return {}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"raw": stdout}

    def _ensure_list(self, value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    def _parse_datetime(self, value: Any) -> datetime | None:
        if not value:
            return None
        if isinstance(value, dict):
            for key in ("value", "DateTime"):
                parsed = self._parse_datetime(value.get(key))
                if parsed:
                    return parsed
            return None
        if isinstance(value, str):
            match = re.fullmatch(r"/Date\((\d+)\)/", value.strip())
            if match:
                return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc)
            candidate = value.replace("Z", "+00:00")
            for fmt in (None, "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y", "%Y%m%d"):
                try:
                    if fmt is None:
                        parsed = datetime.fromisoformat(candidate)
                    else:
                        parsed = datetime.strptime(candidate, fmt)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return parsed.astimezone(timezone.utc)
                except ValueError:
                    continue
        return None

    def _clean_text(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _as_bool(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "enabled", "on"}
        return False

    def _host_name(self, system_profile: dict[str, Any], fallback: str | None) -> str:
        os_data = system_profile.get("os") if isinstance(system_profile.get("os"), dict) else {}
        return os_data.get("CSName") or fallback or "localhost"

    def _bitlocker_protected(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value == 1
        if isinstance(value, str):
            return value.strip().lower() in {"on", "1", "true"}
        return False

    def _is_named_service_account(self, value: Any) -> bool:
        if not value:
            return False
        account = str(value).strip().lower()
        builtins = {
            "localsystem",
            "localservice",
            "networkservice",
            "nt authority\\localservice",
            "nt authority\\networkservice",
            "nt authority\\system",
            "system",
        }
        return account not in builtins
