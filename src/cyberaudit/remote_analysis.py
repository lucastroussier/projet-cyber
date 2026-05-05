from __future__ import annotations

from .models import Finding, HostRecord


class RemoteRiskAnalyzer:
    def analyze(self, hosts: list[HostRecord]) -> list[Finding]:
        findings: list[Finding] = []
        for host in hosts:
            ports = {service.port for service in host.services}
            device = host.device_type or ""

            if 21 in ports:
                findings.append(
                    Finding(
                        title="FTP expose",
                        severity="Medium",
                        target=host.ip,
                        category="Exposed Service",
                        description="Le service FTP est accessible sur l'equipement analyse.",
                        recommendation="Verifier si FTP est necessaire puis preferer SFTP/FTPS et restreindre l'acces reseau.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 23 in ports:
                findings.append(
                    Finding(
                        title="Telnet expose",
                        severity="High",
                        target=host.ip,
                        category="Exposed Service",
                        description="Le service Telnet est accessible sur l'equipement analyse.",
                        recommendation="Desactiver Telnet et utiliser SSH ou une interface d'administration chiffre.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 445 in ports:
                findings.append(
                    Finding(
                        title="SMB expose",
                        severity="Medium",
                        target=host.ip,
                        category="Exposed Service",
                        description="Le partage SMB est accessible depuis le reseau scanne.",
                        recommendation="Limiter l'exposition SMB au strict necessaire et segmenter les acces d'administration.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 3389 in ports:
                findings.append(
                    Finding(
                        title="RDP expose",
                        severity="Medium",
                        target=host.ip,
                        category="Exposed Administration",
                        description="Le service Bureau a distance est accessible depuis le reseau scanne.",
                        recommendation="Restreindre l'acces RDP, utiliser un VPN ou un bastion, puis imposer MFA si possible.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 5985 in ports:
                findings.append(
                    Finding(
                        title="WinRM HTTP expose",
                        severity="High",
                        target=host.ip,
                        category="Remote Administration",
                        description="WinRM en HTTP est expose, ce qui augmente la surface d'administration distante.",
                        recommendation="Verifier la necessite de WinRM, restreindre les ACL et preferer WinRM HTTPS sur 5986.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 5986 in ports:
                findings.append(
                    Finding(
                        title="WinRM HTTPS expose",
                        severity="Medium",
                        target=host.ip,
                        category="Remote Administration",
                        description="WinRM HTTPS est accessible depuis le reseau scanne.",
                        recommendation="Restreindre les hotes autorises et verifier les certificats ainsi que les ACL d'administration.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 5900 in ports:
                findings.append(
                    Finding(
                        title="VNC expose",
                        severity="High",
                        target=host.ip,
                        category="Remote Administration",
                        description="Le service VNC est accessible depuis le reseau scanne.",
                        recommendation="Restreindre l'exposition reseau, imposer un tunnel chiffre et verifier l'authentification.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 873 in ports:
                findings.append(
                    Finding(
                        title="Rsync expose",
                        severity="Medium",
                        target=host.ip,
                        category="Exposed Service",
                        description="Le service rsync est accessible a distance.",
                        recommendation="Verifier si l'exposition est requise, restreindre les clients autorises et imposer l'authentification.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 111 in ports or 2049 in ports:
                findings.append(
                    Finding(
                        title="NFS ou RPC expose",
                        severity="Medium",
                        target=host.ip,
                        category="Exposed Service",
                        description="Des services NFS/RPC sont exposes sur l'equipement analyse.",
                        recommendation="Verifier les exports NFS, les listes de clients autorises et le cloisonnement reseau.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 161 in ports:
                findings.append(
                    Finding(
                        title="SNMP accessible",
                        severity="Medium",
                        target=host.ip,
                        category="Exposed Service",
                        description="Un agent SNMP repond depuis le reseau scanne.",
                        recommendation="Verifier la communaute SNMP, preferer SNMPv3, limiter les ACL et eviter les communautes par defaut.",
                        evidence={"ports": sorted(ports), "services": [service.banner for service in host.services if service.port == 161]},
                    )
                )
            if 5355 in ports:
                findings.append(
                    Finding(
                        title="LLMNR actif",
                        severity="Low",
                        target=host.ip,
                        category="Name Resolution",
                        description="Le service LLMNR a repondu a une sonde de decouverte.",
                        recommendation="Verifier si LLMNR est necessaire. En environnement domaine, preferer DNS et desactiver LLMNR par GPO si possible.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if 137 in ports and 445 not in ports:
                findings.append(
                    Finding(
                        title="NetBIOS expose sans SMB detecte",
                        severity="Info",
                        target=host.ip,
                        category="Asset Discovery",
                        description="Le service NetBIOS Name Service repond mais SMB n'a pas ete detecte dans les ports testes.",
                        recommendation="Verifier l'identite de l'actif et desactiver NetBIOS si l'usage metier n'est plus requis.",
                        evidence={"ports": sorted(ports)},
                    )
                )
            if device in {"nas_synology", "nas_qnap", "nas_generic"} and ({80, 8080, 5000} & ports):
                findings.append(
                    Finding(
                        title="Interface d'administration NAS en HTTP",
                        severity="Medium",
                        target=host.ip,
                        category="Security Configuration",
                        description="Une interface d'administration NAS semble accessible en HTTP non chiffre.",
                        recommendation="Preferer HTTPS, limiter l'exposition a un reseau d'administration et verifier l'authentification forte.",
                        evidence={"ports": sorted(ports), "fingerprint": host.fingerprint},
                    )
                )
            if host.device_type == "equipement_reseau_detecte":
                findings.append(
                    Finding(
                        title="Equipement non identifie",
                        severity="Info",
                        target=host.ip,
                        category="Asset Discovery",
                        description="Un equipement a ete detecte sur le reseau sans reponse exploitable aux ports testes.",
                        recommendation="Completer l'inventaire d'actifs, verifier son proprietaire et elargir eventuellement la liste de ports controles.",
                        evidence={"notes": host.notes},
                    )
                )
        return findings
