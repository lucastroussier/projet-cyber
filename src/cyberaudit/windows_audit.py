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
    Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, AntispywareSignatureAge, NISEnabled, NISSignatureAge, QuickScanAge, FullScanAge, AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime, IoavProtectionEnabled, BehaviorMonitorEnabled, OnAccessProtectionEnabled, IsTamperProtected
} else {
  $defender = [PSCustomObject]@{ available = $false }
}
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
  $defenderPreference = Get-MpPreference -ErrorAction SilentlyContinue |
    Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, DisableBlockAtFirstSeen, DisableScriptScanning, DisableArchiveScanning, PUAProtection, MAPSReporting, SubmitSamplesConsent, EnableControlledFolderAccess
} else {
  $defenderPreference = [PSCustomObject]@{ available = $false }
}
$rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
$rdpTcp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
$dnsClientPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
$smb = $null
if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
  $smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
}
$smbConfig = $null
if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
  $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue |
    Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EnableSecuritySignature, RequireSecuritySignature, EncryptData, RejectUnencryptedAccess, EnableAuthenticateUserSharing, EnableForcedLogoff
}
$secureBoot = $null
try {
  $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
} catch {
  $secureBoot = $null
}
$tpm = $null
if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
  $tpm = Get-Tpm -ErrorAction SilentlyContinue |
    Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManagedAuthLevel
}
$deviceGuard = $null
try {
  $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop |
    Select-Object SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus, RequiredSecurityProperties, AvailableSecurityProperties
} catch {
  $deviceGuard = $null
}
$smb1State = 'Unknown'
if ($smbConfig -and $null -ne $smbConfig.EnableSMB1Protocol) {
  if ($smbConfig.EnableSMB1Protocol) { $smb1State = 'Enabled' } else { $smb1State = 'Disabled' }
} elseif ($smb) {
  $smb1State = [string]$smb.State
}
$rdpNla = $null
if ($rdpTcp -and $null -ne $rdpTcp.UserAuthentication) {
  $rdpNla = [bool]($rdpTcp.UserAuthentication -eq 1)
}
$lsaRunAsPpl = $false
if ($lsa -and $null -ne $lsa.RunAsPPL) {
  $lsaRunAsPpl = [bool]([int]$lsa.RunAsPPL -gt 0)
}
$credentialGuardRunning = $false
if ($deviceGuard -and $deviceGuard.SecurityServicesRunning) {
  $credentialGuardRunning = [bool]($deviceGuard.SecurityServicesRunning -contains 1)
}
$security = [PSCustomObject]@{
  rdpEnabled = [bool]($rdp -and $rdp.fDenyTSConnections -eq 0)
  rdpNetworkLevelAuthenticationEnabled = $rdpNla
  rdpSecurityLayer = if ($rdpTcp) { $rdpTcp.SecurityLayer } else { $null }
  uacEnabled = [bool]($uac -and $uac.EnableLUA -eq 1)
  smb1State = $smb1State
  smbServer = $smbConfig
  llmnrEnabled = [bool](-not ($dnsClientPolicy -and $dnsClientPolicy.EnableMulticast -eq 0))
  lsassRunAsPpl = $lsaRunAsPpl
  secureBootEnabled = $secureBoot
  tpm = $tpm
  credentialGuardRunning = $credentialGuardRunning
  deviceGuard = $deviceGuard
}
$pendingFileRename = $false
$sessionManager = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
if ($sessionManager -and $sessionManager.PendingFileRenameOperations) {
  $pendingFileRename = $true
}
$pendingReboot = [PSCustomObject]@{
  componentBasedServicing = [bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
  windowsUpdate = [bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
  pendingFileRename = $pendingFileRename
}
$wuPolicy = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
$windowsUpdate = [PSCustomObject]@{
  noAutoUpdate = if ($wuPolicy) { $wuPolicy.NoAutoUpdate } else { $null }
  auOptions = if ($wuPolicy) { $wuPolicy.AUOptions } else { $null }
  scheduledInstallDay = if ($wuPolicy) { $wuPolicy.ScheduledInstallDay } else { $null }
  scheduledInstallTime = if ($wuPolicy) { $wuPolicy.ScheduledInstallTime } else { $null }
}
$updateServices = @()
try {
  $updateServices = @(Get-Service -Name wuauserv,bits,cryptsvc -ErrorAction SilentlyContinue |
    Select-Object Name, DisplayName, Status, StartType)
} catch {
  $updateServices = @([PSCustomObject]@{ error = $_.Exception.Message })
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
$localUsers = @()
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
  try {
    $localUsers = @(Get-LocalUser -ErrorAction Stop |
      Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, PasswordExpires, UserMayChangePassword, Description, SID)
  } catch {
    $localUsers = @([PSCustomObject]@{ error = $_.Exception.Message })
  }
}
$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.State -eq 'Running' -or $_.StartMode -eq 'Auto' } |
  Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
  Sort-Object DisplayName |
  Select-Object -First 200)
$tcpListeners = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
  $processCache = @{}
  $tcpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object {
      $pidValue = $_.OwningProcess
      if (-not $processCache.ContainsKey($pidValue)) {
        $process = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
        if ($process) { $processCache[$pidValue] = $process.ProcessName } else { $processCache[$pidValue] = $null }
      }
      [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        OwningProcess = $pidValue
        ProcessName = $processCache[$pidValue]
      }
    } |
    Sort-Object LocalPort, LocalAddress |
    Select-Object -First 300)
}
$networkProfiles = @()
if (Get-Command Get-NetConnectionProfile -ErrorAction SilentlyContinue) {
  $networkProfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity)
}
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
  defender_preferences = $defenderPreference
  security = $security
  pending_reboot = $pendingReboot
  windows_update = $windowsUpdate
  update_services = $updateServices
  bitlocker = $bitlocker
  local_admins = $localAdmins
  local_users = $localUsers
  services = $services
  tcp_listeners = $tcpListeners
  network_profiles = $networkProfiles
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

        software_inventory = self._software_inventory_from_payload(payload, target)

        system_profile = payload.get("system_profile") if isinstance(payload.get("system_profile"), dict) else {}
        hotfixes = payload.get("hotfixes")
        firewalls = payload.get("firewall_profiles")
        defender = payload.get("defender") if isinstance(payload.get("defender"), dict) else {}
        security = payload.get("security") if isinstance(payload.get("security"), dict) else {}

        findings = self._build_findings(system_profile, hotfixes, firewalls, defender, security, payload)
        findings.extend(self._build_extended_findings(payload, target))
        for finding in findings:
            finding.source = source

        metadata = dict(payload)
        if target:
            metadata["target"] = target
        metadata["collection_mode"] = source
        return WindowsAuditResult(findings=findings, software_inventory=software_inventory, metadata=metadata)

    def _software_inventory_from_payload(self, payload: dict[str, Any], target: str | None) -> list[SoftwareRecord]:
        records: list[SoftwareRecord] = []
        os_record = self._os_as_software(payload, target)
        if os_record:
            records.append(os_record)

        for item in self._ensure_list(payload.get("software_inventory")):
            name = self._clean_text(item.get("DisplayName"))
            if not name:
                continue
            records.append(
                SoftwareRecord(
                    name=name,
                    version=self._clean_text(item.get("DisplayVersion")),
                    vendor=self._clean_text(item.get("Publisher")),
                    install_date=self._clean_text(item.get("InstallDate")),
                    host=target,
                )
            )
        return self._dedupe_software(records)

    def _os_as_software(self, payload: dict[str, Any], target: str | None) -> SoftwareRecord | None:
        system_profile = payload.get("system_profile") if isinstance(payload.get("system_profile"), dict) else {}
        os_data = system_profile.get("os") if isinstance(system_profile.get("os"), dict) else {}
        caption = self._clean_text(os_data.get("Caption"))
        if not caption:
            return None
        version = self._clean_text(os_data.get("Version"))
        build = self._clean_text(os_data.get("BuildNumber"))
        version_label = " ".join(part for part in [version, f"build {build}" if build else None] if part)
        return SoftwareRecord(
            name=caption,
            version=version_label or version or build,
            vendor="Microsoft",
            install_date=None,
            host=target,
        )

    def _dedupe_software(self, records: list[SoftwareRecord]) -> list[SoftwareRecord]:
        deduped: list[SoftwareRecord] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in records:
            key = (
                item.name.strip().lower(),
                (item.version or "").strip().lower(),
                (item.vendor or "").strip().lower(),
                (item.host or "").strip().lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

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
        payload: dict[str, Any],
    ) -> list[Finding]:
        findings: list[Finding] = []
        host_name = self._host_name(system_profile, None)
        defender_preferences = payload.get("defender_preferences") if isinstance(payload.get("defender_preferences"), dict) else {}

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
            if defender.get("AMServiceEnabled") is False or defender.get("AntivirusEnabled") is False:
                findings.append(
                    Finding(
                        title="Antivirus inactif",
                        severity="High",
                        target=host_name,
                        category="Endpoint Protection",
                        description="Le moteur antivirus Microsoft Defender ne remonte pas comme actif.",
                        recommendation="Verifier l'antivirus installe, l'etat du service Defender et les politiques de securite appliquees.",
                        evidence=defender,
                    )
                )
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
            if defender.get("BehaviorMonitorEnabled") is False or defender_preferences.get("DisableBehaviorMonitoring") is True:
                findings.append(
                    Finding(
                        title="Surveillance comportementale Defender desactivee",
                        severity="Medium",
                        target=host_name,
                        category="Endpoint Protection",
                        description="La surveillance comportementale Defender semble desactivee.",
                        recommendation="Reactiver la surveillance comportementale sauf exception documentee par une politique de securite.",
                        evidence={"status": defender, "preferences": defender_preferences},
                    )
                )
            if defender.get("IoavProtectionEnabled") is False or defender_preferences.get("DisableIOAVProtection") is True:
                findings.append(
                    Finding(
                        title="Analyse des fichiers telecharges desactivee",
                        severity="Medium",
                        target=host_name,
                        category="Endpoint Protection",
                        description="La protection IOAV de Defender semble desactivee pour les fichiers telecharges ou ouverts depuis Internet.",
                        recommendation="Reactiver IOAV et verifier les exceptions configurees.",
                        evidence={"status": defender, "preferences": defender_preferences},
                    )
                )
            pua_protection = defender_preferences.get("PUAProtection")
            if isinstance(pua_protection, int) and pua_protection == 0:
                findings.append(
                    Finding(
                        title="Protection contre les applications indesirables desactivee",
                        severity="Low",
                        target=host_name,
                        category="Endpoint Protection",
                        description="La protection Defender contre les applications potentiellement indesirables est desactivee.",
                        recommendation="Activer PUAProtection en mode blocage ou audit selon la politique de l'organisation.",
                        evidence={"PUAProtection": pua_protection},
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
        smb_server = security.get("smbServer") if isinstance(security.get("smbServer"), dict) else {}
        if smb_server.get("RequireSecuritySignature") is False:
            findings.append(
                Finding(
                    title="Signature SMB non obligatoire",
                    severity="Medium",
                    target=host_name,
                    category="Security Configuration",
                    description="Le serveur SMB n'exige pas la signature des communications.",
                    recommendation="Exiger la signature SMB sur les postes qui exposent des partages ou des services d'administration.",
                    evidence=smb_server,
                )
            )
        if smb_server.get("RejectUnencryptedAccess") is False:
            findings.append(
                Finding(
                    title="SMB accepte les acces non chiffres",
                    severity="Medium",
                    target=host_name,
                    category="Security Configuration",
                    description="La configuration SMB n'impose pas le rejet des acces non chiffres.",
                    recommendation="Activer le rejet des connexions SMB non chiffrees quand les clients et serveurs le supportent.",
                    evidence=smb_server,
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
        if security.get("llmnrEnabled") is True:
            findings.append(
                Finding(
                    title="LLMNR actif",
                    severity="Low",
                    target=host_name,
                    category="Network Hardening",
                    description="LLMNR semble autorise, ce qui peut exposer le poste a des attaques de resolution de noms sur le LAN.",
                    recommendation="Desactiver LLMNR par GPO si l'environnement n'en a pas besoin.",
                    evidence=security,
                )
            )
        if security.get("lsassRunAsPpl") is False:
            findings.append(
                Finding(
                    title="Protection LSASS non active",
                    severity="Medium",
                    target=host_name,
                    category="Credential Protection",
                    description="LSASS ne semble pas lance en mode Protected Process Light.",
                    recommendation="Activer la protection LSA/RunAsPPL apres validation de compatibilite avec les agents de securite.",
                    evidence=security,
                )
            )
        if security.get("secureBootEnabled") is False:
            findings.append(
                Finding(
                    title="Secure Boot desactive",
                    severity="Medium",
                    target=host_name,
                    category="Boot Security",
                    description="Secure Boot est desactive ou non actif sur ce poste.",
                    recommendation="Activer Secure Boot dans l'UEFI lorsque le materiel et l'image Windows le permettent.",
                    evidence=security,
                )
            )
        tpm = security.get("tpm") if isinstance(security.get("tpm"), dict) else {}
        if tpm and (tpm.get("TpmPresent") is False or tpm.get("TpmReady") is False):
            findings.append(
                Finding(
                    title="TPM absent ou non pret",
                    severity="Low",
                    target=host_name,
                    category="Boot Security",
                    description="Le TPM n'est pas present ou pas pret, ce qui limite certaines protections locales.",
                    recommendation="Verifier l'activation TPM dans l'UEFI et la compatibilite materielle.",
                    evidence=tpm,
                )
            )
        if security.get("credentialGuardRunning") is False:
            findings.append(
                Finding(
                    title="Credential Guard non actif",
                    severity="Low",
                    target=host_name,
                    category="Credential Protection",
                    description="Credential Guard ne semble pas actif sur ce poste.",
                    recommendation="Evaluer l'activation de Credential Guard sur les postes compatibles, surtout pour les administrateurs.",
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
            if security.get("rdpNetworkLevelAuthenticationEnabled") is False:
                findings.append(
                    Finding(
                        title="RDP actif sans NLA",
                        severity="High",
                        target=host_name,
                        category="Exposed Administration",
                        description="RDP est actif sans authentification au niveau du reseau.",
                        recommendation="Activer NLA pour RDP et limiter l'exposition aux sources autorisees.",
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

        pending_reboot = payload.get("pending_reboot") if isinstance(payload.get("pending_reboot"), dict) else {}
        if any(self._as_bool(value) for value in pending_reboot.values()):
            findings.append(
                Finding(
                    title="Redemarrage de securite en attente",
                    severity="Medium",
                    target=host_name,
                    category="Patch Management",
                    description="Windows indique qu'un redemarrage est en attente apres installation ou modification systeme.",
                    recommendation="Planifier un redemarrage pour finaliser l'application des correctifs et changements systeme.",
                    evidence=pending_reboot,
                )
            )

        windows_update = payload.get("windows_update") if isinstance(payload.get("windows_update"), dict) else {}
        if self._as_bool(windows_update.get("noAutoUpdate")):
            findings.append(
                Finding(
                    title="Mises a jour automatiques Windows desactivees",
                    severity="High",
                    target=host_name,
                    category="Patch Management",
                    description="La politique locale indique que Windows Update automatique est desactive.",
                    recommendation="Reactiver la gestion automatique des correctifs ou documenter la prise en charge par un outil de patch management.",
                    evidence=windows_update,
                )
            )

        disabled_update_services = [
            item
            for item in self._ensure_list(payload.get("update_services"))
            if str(item.get("StartType", "")).lower() == "disabled"
        ]
        if disabled_update_services:
            findings.append(
                Finding(
                    title="Services Windows Update desactives",
                    severity="High",
                    target=host_name,
                    category="Patch Management",
                    description="Un ou plusieurs services necessaires aux mises a jour Windows sont desactives.",
                    recommendation="Verifier les services Windows Update, BITS et Cryptographic Services ou la politique de patch management equivalente.",
                    evidence={"services": disabled_update_services},
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

        users = [item for item in self._ensure_list(payload.get("local_users")) if not item.get("error")]
        enabled_guest_accounts = [item for item in users if self._as_bool(item.get("Enabled")) and self._is_guest_account(item)]
        if enabled_guest_accounts:
            findings.append(
                Finding(
                    title="Compte invite local actif",
                    severity="High",
                    target=host_name,
                    category="Identity and Access",
                    description="Un compte invite local est actif.",
                    recommendation="Desactiver les comptes invites et utiliser des comptes nominatifs controles.",
                    evidence={"users": enabled_guest_accounts},
                )
            )

        no_password_users = [
            item
            for item in users
            if self._as_bool(item.get("Enabled")) and self._account_has_no_password_required(item)
        ]
        if no_password_users:
            findings.append(
                Finding(
                    title="Compte local actif sans mot de passe requis",
                    severity="High",
                    target=host_name,
                    category="Identity and Access",
                    description="Un ou plusieurs comptes locaux actifs n'exigent pas de mot de passe.",
                    recommendation="Imposer un mot de passe aux comptes locaux actifs ou les desactiver s'ils ne sont pas requis.",
                    evidence={"users": no_password_users[:10]},
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

        unquoted_services = [
            item
            for item in self._ensure_list(payload.get("services"))
            if self._has_unquoted_service_path(item.get("PathName"))
        ]
        if unquoted_services:
            findings.append(
                Finding(
                    title="Chemins de services non cites",
                    severity="High",
                    target=host_name,
                    category="Local Privilege Escalation",
                    description="Des services automatiques ou actifs utilisent un chemin executable avec espaces sans guillemets.",
                    recommendation="Corriger les chemins de services en ajoutant des guillemets autour de l'executable et verifier les ACL des dossiers parents.",
                    evidence={"services": unquoted_services[:10]},
                )
            )

        risky_listeners = [
            item
            for item in self._ensure_list(payload.get("tcp_listeners"))
            if self._is_risky_listener(item)
        ]
        if risky_listeners:
            findings.append(
                Finding(
                    title="Ports locaux sensibles en ecoute",
                    severity="Medium",
                    target=host_name,
                    category="Exposed Services",
                    description="Des ports d'administration ou de donnees sensibles ecoutent sur une adresse non strictement locale.",
                    recommendation="Verifier le besoin de chaque service, restreindre par pare-feu et limiter l'exposition aux reseaux autorises.",
                    evidence={"listeners": risky_listeners[:20]},
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

    def _is_guest_account(self, item: dict[str, Any]) -> bool:
        name = str(item.get("Name", "")).strip().lower()
        sid = str(item.get("SID", "")).strip()
        return name in {"guest", "invite"} or sid.endswith("-501")

    def _account_has_no_password_required(self, item: dict[str, Any]) -> bool:
        if self._is_guest_account(item):
            return False
        password_required = item.get("PasswordRequired")
        if isinstance(password_required, bool):
            return not password_required
        if isinstance(password_required, str):
            return password_required.strip().lower() in {"false", "0", "no", "non"}
        return False

    def _has_unquoted_service_path(self, value: Any) -> bool:
        if not value:
            return False
        path = str(value).strip()
        if not path or path.startswith('"'):
            return False
        lower = path.lower()
        if not lower.endswith(".exe") and ".exe " not in lower:
            return False
        executable = path[: lower.find(".exe") + 4] if ".exe" in lower else path
        return " " in executable

    def _is_risky_listener(self, item: dict[str, Any]) -> bool:
        try:
            port = int(item.get("LocalPort"))
        except (TypeError, ValueError):
            return False
        if port not in {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017}:
            return False
        address = str(item.get("LocalAddress", "")).strip().lower()
        return address not in {"127.0.0.1", "::1", "localhost"}
