from __future__ import annotations

import ipaddress
import json
import platform
import random
import re
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import ScanConfig
from .models import HostRecord, ServiceRecord


COMMON_SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    88: "kerberos",
    111: "rpcbind",
    80: "http",
    110: "pop3",
    135: "rpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    464: "kpasswd",
    548: "afp",
    593: "http-rpc-epmap",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5000: "synology-dsm-http",
    5001: "synology-dsm-https",
    5357: "wsdapi",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8081: "http-admin",
    8088: "http-alt",
    8090: "http-alt",
    8091: "http-alt",
    8443: "https-alt",
    9000: "http-alt",
    9001: "http-alt",
    9090: "http-admin",
    9091: "http-admin",
    9200: "elasticsearch",
    10000: "webmin",
    1311: "qnap-web",
    32400: "plex",
    3268: "globalcatalog",
    3269: "globalcatalog-ssl",
    9389: "adws",
    27017: "mongodb",
}
HTTP_LIKE_PORTS = {80, 443, 5000, 5001, 5357, 8080, 8081, 8088, 8090, 8091, 8443, 9000, 9001, 9090, 9091, 9200, 10000, 1311, 32400}
SSH_LIKE_PORTS = {22}
TEXT_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 3306, 5432, 6379}
UDP_SERVICE_NAMES = {
    53: "dns",
    123: "ntp",
    137: "netbios-ns",
    161: "snmp",
    5353: "mdns",
    5355: "llmnr",
}


class NetworkScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def scan(self) -> list[HostRecord]:
        if not self.config.network_cidr:
            return []

        network = ipaddress.ip_network(self.config.network_cidr, strict=False)
        self._validate_network(network)

        hosts = list(network.hosts())
        if len(hosts) > self.config.max_hosts:
            raise ValueError(
                f"Sous-reseau trop large ({len(hosts)} hotes). Augmentez max_hosts dans la configuration pour un audit plus vaste."
            )

        neighbors = self._read_arp_neighbors(network)
        candidates: dict[str, tuple[bool, float | None]] = {}
        with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
            futures = {executor.submit(self._discover_host, str(ip)): str(ip) for ip in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                alive, latency = future.result()
                if alive or ip in neighbors:
                    candidates[ip] = (alive or ip in neighbors, latency)

        discovered: list[HostRecord] = []
        detail_workers = max(16, min(self.config.workers, 96))
        with ThreadPoolExecutor(max_workers=detail_workers) as executor:
            futures = {
                executor.submit(self._scan_host, ip, candidates[ip][0], candidates[ip][1], neighbors.get(ip)): ip
                for ip in candidates
            }
            for future in as_completed(futures):
                host = future.result()
                if host:
                    discovered.append(host)

        return sorted(discovered, key=lambda item: tuple(int(part) for part in item.ip.split(".")))

    def _validate_network(self, network: ipaddress._BaseNetwork) -> None:
        if self.config.allow_non_private_targets:
            return

        test_ip = next(network.hosts(), network.network_address)
        if not (test_ip.is_private or test_ip.is_loopback):
            raise ValueError(
                "Le scan est restreint aux plages privees/loopback par defaut. Activez allow_non_private_targets seulement pour un audit autorise."
            )

    def _discover_host(self, ip: str) -> tuple[bool, float | None]:
        alive, latency = self._ping_host(ip, timeout=self.config.discovery_timeout)
        if alive:
            return True, latency
        for port in self.config.discovery_ports:
            if self._is_port_open(ip, port, self.config.discovery_timeout):
                return True, latency
        if self.config.enable_udp_discovery:
            for port in self.config.udp_discovery_ports:
                if self._probe_udp_port(ip, port):
                    return True, latency
        return False, latency

    def _scan_host(self, ip: str, alive_hint: bool, latency_hint: float | None, mac_address: str | None) -> HostRecord | None:
        services = self._scan_ports(ip)
        services.extend(self._scan_udp_services(ip))
        services = sorted(services, key=lambda item: (item.port, item.protocol))
        if not alive_hint and not services and not mac_address:
            return None

        hostname = self._resolve_hostname(ip) or self._hostname_from_services(services)
        operating_system, device_type, fingerprint = self._classify_host(services, hostname)
        notes = []
        if services and not alive_hint:
            notes.append("Hote detecte via ports ouverts uniquement.")
        if alive_hint and not services:
            notes.append("Hote joignable mais aucun des ports testes n'est ouvert.")
        if mac_address:
            notes.append(f"Adresse MAC: {mac_address}")
        if mac_address and not services:
            notes.append("Hote confirme via cache ARP local.")
        if any(service.protocol == "udp" for service in services):
            notes.append("Reponse UDP de decouverte recue.")

        return HostRecord(
            ip=ip,
            hostname=hostname,
            is_alive=alive_hint or bool(services) or bool(mac_address),
            latency_ms=latency_hint,
            services=services,
            operating_system=operating_system,
            device_type=device_type,
            fingerprint=fingerprint,
            notes=notes,
        )

    def _ping_host(self, ip: str, timeout: float | None = None) -> tuple[bool, float | None]:
        system = platform.system().lower()
        timeout_ms = int((timeout or self.config.connect_timeout) * 1000)
        if system == "windows":
            command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            command = ["ping", "-c", "1", "-W", "1", ip]

        start = time.perf_counter()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=max(2, timeout or 1), check=False)
        except (OSError, subprocess.SubprocessError):
            return False, None
        latency = (time.perf_counter() - start) * 1000
        return result.returncode == 0, round(latency, 1)

    def _scan_ports(self, ip: str) -> list[ServiceRecord]:
        services: list[ServiceRecord] = []
        if not self.config.ports:
            return services
        with ThreadPoolExecutor(max_workers=min(self.config.port_workers, len(self.config.ports))) as executor:
            futures = {executor.submit(self._probe_port, ip, port, self.config.connect_timeout): port for port in self.config.ports}
            for future in as_completed(futures):
                service = future.result()
                if service:
                    services.append(service)
        return sorted(services, key=lambda item: item.port)

    def _probe_port(self, ip: str, port: int, timeout: float) -> ServiceRecord | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) != 0:
                    return None
                banner = self._grab_banner(sock, port)
        except OSError:
            return None

        service_name = COMMON_SERVICE_NAMES.get(port) or self._safe_service_name(port)
        product, version, vendor = self._fingerprint_service(port, banner)
        return ServiceRecord(
            port=port,
            protocol="tcp",
            service=service_name,
            banner=banner,
            product=product,
            version=version,
            vendor=vendor,
        )

    def _grab_banner(self, sock: socket.socket, port: int) -> str | None:
        try:
            sock.settimeout(self.config.banner_timeout)
            if port in HTTP_LIKE_PORTS:
                sock.sendall(b"GET / HTTP/1.0\r\nHost: audit.local\r\nUser-Agent: CyberAudit\r\n\r\n")
            elif port in TEXT_BANNER_PORTS:
                pass
            chunks: list[bytes] = []
            for _ in range(3):
                data = sock.recv(384)
                if not data:
                    break
                chunks.append(data)
                if sum(len(chunk) for chunk in chunks) >= 1024:
                    break
            if not chunks:
                return None
            banner = b"".join(chunks).decode(errors="ignore").strip().replace("\x00", "")
            banner = re.sub(r"\s+", " ", banner)
            return banner[:500] if banner else None
        except OSError:
            return None

    def _resolve_hostname(self, ip: str) -> str | None:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except OSError:
            return None

    def _classify_host(self, services: list[ServiceRecord], hostname: str | None) -> tuple[str | None, str | None, str | None]:
        ports = {service.port for service in services}
        host_lower = (hostname or "").lower()
        combined_text = " ".join(
            part.lower()
            for service in services
            for part in [service.banner or "", service.product or "", service.vendor or ""]
            if part
        )

        if "printer" in combined_text or "imprimante" in combined_text or 9100 in ports or 515 in ports or 631 in ports:
            return None, "imprimante", "Imprimante ou serveur d'impression probable"
        if 161 in ports and any(token in combined_text for token in ["router", "switch", "firewall", "fortinet", "cisco", "hp procurve"]):
            return None, "equipement_reseau", "Equipement reseau probable via SNMP"
        if "synology" in combined_text or "diskstation" in combined_text or 5000 in ports or 5001 in ports:
            return "Linux/Embedded probable", "nas_synology", "Synology DSM probable"
        if "qnap" in combined_text or " qts" in combined_text or "quts" in combined_text or 1311 in ports:
            return "Linux/Embedded probable", "nas_qnap", "QNAP NAS probable"
        if "nas" in host_lower or ({139, 445} & ports and {80, 443, 5000, 5001, 8080, 8081, 873} & ports):
            return "Linux/Embedded probable", "nas_generic", "NAS probable"
        if 5985 in ports or 5986 in ports or 3389 in ports or 135 in ports or ({445, 139} <= ports and 22 not in ports):
            return "Windows probable", "poste_ou_serveur_windows", "Empreinte Windows probable"
        if 22 in ports and 445 not in ports:
            return "Linux/Unix probable", "serveur_linux", "Empreinte Linux/Unix probable"
        if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
            return None, "serveur_web_ou_appliance", "Appliance ou serveur web probable"
        if 23 in ports:
            return None, "equipement_reseau_legacy", "Equipement legacy probable"
        if "router" in host_lower or "fw" in host_lower:
            return None, "routeur_pare_feu", "Routeur ou pare-feu probable"
        return None, None, None

    def _hostname_from_services(self, services: list[ServiceRecord]) -> str | None:
        for service in services:
            if service.protocol == "udp" and service.port == 137 and service.version:
                return service.version
            if service.protocol == "udp" and service.port == 161 and service.version:
                return service.version
        return None

    def _safe_service_name(self, port: int) -> str:
        try:
            return socket.getservbyport(port)
        except OSError:
            return "unknown"

    def _is_port_open(self, ip: str, port: int, timeout: float) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return sock.connect_ex((ip, port)) == 0
        except OSError:
            return False

    def _scan_udp_services(self, ip: str) -> list[ServiceRecord]:
        if not self.config.enable_udp_discovery:
            return []
        services: list[ServiceRecord] = []
        for port in self.config.udp_discovery_ports:
            service = self._probe_udp_port(ip, port)
            if service:
                services.append(service)
        return services

    def _probe_udp_port(self, ip: str, port: int) -> ServiceRecord | None:
        if port == 137:
            return self._probe_netbios(ip)
        if port == 161:
            return self._probe_snmp(ip)
        if port == 5353:
            return self._probe_mdns(ip)
        if port == 5355:
            return self._probe_llmnr(ip)
        return self._probe_generic_udp(ip, port)

    def _probe_generic_udp(self, ip: str, port: int) -> ServiceRecord | None:
        payloads = {
            53: self._build_dns_query("version.bind", qtype=16, query_id=random.randint(1, 65535)),
            123: b"\x1b" + b"\x00" * 47,
        }
        data = self._udp_request(ip, port, payloads.get(port, b"\x00"))
        if not data:
            return None
        return ServiceRecord(
            port=port,
            protocol="udp",
            service=UDP_SERVICE_NAMES.get(port) or self._safe_service_name(port),
            banner=self._format_udp_banner(data),
        )

    def _probe_netbios(self, ip: str) -> ServiceRecord | None:
        transaction_id = random.randint(1, 65535)
        packet = (
            struct.pack(">HHHHHH", transaction_id, 0x0000, 1, 0, 0, 0)
            + self._encode_netbios_name("*")
            + struct.pack(">HH", 0x0021, 0x0001)
        )
        data = self._udp_request(ip, 137, packet)
        if not data:
            return None
        names = self._parse_netbios_names(data)
        primary_name = names[0] if names else None
        banner = f"NetBIOS names: {', '.join(names[:8])}" if names else self._format_udp_banner(data)
        return ServiceRecord(
            port=137,
            protocol="udp",
            service="netbios-ns",
            banner=banner,
            product="NetBIOS Name Service",
            version=primary_name,
        )

    def _probe_snmp(self, ip: str) -> ServiceRecord | None:
        for community in self.config.snmp_communities:
            packet = self._build_snmp_get_request(
                community,
                [
                    (1, 3, 6, 1, 2, 1, 1, 1, 0),  # sysDescr.0
                    (1, 3, 6, 1, 2, 1, 1, 5, 0),  # sysName.0
                ],
            )
            data = self._udp_request(ip, 161, packet)
            if not data:
                continue
            strings = [item for item in self._extract_ber_strings(data) if item != community]
            sys_descr = strings[0] if strings else self._format_udp_banner(data)
            sys_name = strings[1] if len(strings) > 1 else None
            return ServiceRecord(
                port=161,
                protocol="udp",
                service="snmp",
                banner=sys_descr,
                product="SNMP agent",
                version=sys_name,
            )
        return None

    def _probe_mdns(self, ip: str) -> ServiceRecord | None:
        packet = self._build_dns_query("_services._dns-sd._udp.local", qtype=12, query_id=0)
        data = self._udp_request(ip, 5353, packet)
        if not data:
            return None
        names = self._extract_dns_names(data)
        banner = "mDNS: " + ", ".join(names[:6]) if names else self._format_udp_banner(data)
        return ServiceRecord(port=5353, protocol="udp", service="mdns", banner=banner, product="mDNS responder")

    def _probe_llmnr(self, ip: str) -> ServiceRecord | None:
        packet = self._build_dns_query("wpad", qtype=1, query_id=random.randint(1, 65535))
        data = self._udp_request(ip, 5355, packet)
        if not data:
            return None
        names = self._extract_dns_names(data)
        banner = "LLMNR: " + ", ".join(names[:6]) if names else self._format_udp_banner(data)
        return ServiceRecord(port=5355, protocol="udp", service="llmnr", banner=banner, product="LLMNR responder")

    def _udp_request(self, ip: str, port: int, payload: bytes) -> bytes | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.config.udp_timeout)
                sock.sendto(payload, (ip, port))
                data, _ = sock.recvfrom(2048)
                return data
        except OSError:
            return None

    def _format_udp_banner(self, data: bytes) -> str:
        text = data.decode(errors="ignore")
        text = re.sub(r"\s+", " ", text).strip()
        if text and sum(1 for char in text if char.isprintable()) >= max(1, len(text) // 2):
            return text[:300]
        return f"{len(data)} octets UDP recus"

    def _encode_netbios_name(self, name: str) -> bytes:
        padded = name.upper().ljust(16)[:16]
        encoded = []
        for char in padded:
            value = ord(char)
            encoded.append(chr(((value >> 4) & 0x0F) + ord("A")))
            encoded.append(chr((value & 0x0F) + ord("A")))
        return bytes([32]) + "".join(encoded).encode("ascii") + b"\x00"

    def _parse_netbios_names(self, data: bytes) -> list[str]:
        try:
            qdcount, ancount = struct.unpack(">HH", data[4:8])
            offset = 12
            for _ in range(qdcount):
                offset = self._skip_dns_name(data, offset) + 4
            names: list[str] = []
            for _ in range(ancount):
                offset = self._skip_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                _, _, _, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
                offset += 10
                rdata = data[offset : offset + rdlength]
                offset += rdlength
                if not rdata:
                    continue
                count = rdata[0]
                cursor = 1
                for _ in range(count):
                    if cursor + 18 > len(rdata):
                        break
                    raw_name = rdata[cursor : cursor + 15].decode(errors="ignore").strip()
                    cursor += 18
                    if raw_name and raw_name not in names:
                        names.append(raw_name)
                return names
        except (OSError, struct.error, UnicodeDecodeError, IndexError):
            return []
        return []

    def _build_dns_query(self, name: str, qtype: int, query_id: int) -> bytes:
        return (
            struct.pack(">HHHHHH", query_id, 0x0000, 1, 0, 0, 0)
            + self._encode_dns_name(name)
            + struct.pack(">HH", qtype, 1)
        )

    def _encode_dns_name(self, name: str) -> bytes:
        encoded = bytearray()
        for label in name.rstrip(".").split("."):
            label_bytes = label.encode("ascii", errors="ignore")[:63]
            encoded.append(len(label_bytes))
            encoded.extend(label_bytes)
        encoded.append(0)
        return bytes(encoded)

    def _extract_dns_names(self, data: bytes) -> list[str]:
        names: list[str] = []
        for offset in range(12, min(len(data), 512)):
            try:
                name, _ = self._read_dns_name(data, offset)
            except (IndexError, ValueError):
                continue
            if "." in name and name not in names:
                names.append(name)
        return names

    def _read_dns_name(self, data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
        if depth > 8:
            raise ValueError("compression DNS trop profonde")
        labels: list[str] = []
        cursor = offset
        jumped = False
        next_offset = cursor
        while True:
            if cursor >= len(data):
                raise IndexError("nom DNS hors limites")
            length = data[cursor]
            if length == 0:
                cursor += 1
                if not jumped:
                    next_offset = cursor
                break
            if length & 0xC0 == 0xC0:
                if cursor + 1 >= len(data):
                    raise IndexError("pointeur DNS hors limites")
                pointer = ((length & 0x3F) << 8) | data[cursor + 1]
                pointed, _ = self._read_dns_name(data, pointer, depth + 1)
                if pointed:
                    labels.append(pointed)
                cursor += 2
                if not jumped:
                    next_offset = cursor
                jumped = True
                break
            if length & 0xC0:
                raise ValueError("label DNS invalide")
            cursor += 1
            label = data[cursor : cursor + length].decode("ascii", errors="ignore")
            if not label:
                raise ValueError("label DNS vide")
            labels.append(label)
            cursor += length
            if not jumped:
                next_offset = cursor
        return ".".join(labels), next_offset

    def _skip_dns_name(self, data: bytes, offset: int) -> int:
        _, next_offset = self._read_dns_name(data, offset)
        return next_offset

    def _build_snmp_get_request(self, community: str, oids: list[tuple[int, ...]]) -> bytes:
        request_id = random.randint(1, 2_147_483_647)
        varbinds = b"".join(
            self._ber_tlv(0x30, self._ber_oid(oid) + self._ber_tlv(0x05, b""))
            for oid in oids
        )
        pdu = self._ber_tlv(
            0xA0,
            self._ber_int(request_id)
            + self._ber_int(0)
            + self._ber_int(0)
            + self._ber_tlv(0x30, varbinds),
        )
        return self._ber_tlv(0x30, self._ber_int(0) + self._ber_octet_string(community) + pdu)

    def _ber_tlv(self, tag: int, value: bytes) -> bytes:
        return bytes([tag]) + self._ber_length(len(value)) + value

    def _ber_length(self, length: int) -> bytes:
        if length < 128:
            return bytes([length])
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(raw)]) + raw

    def _ber_int(self, value: int) -> bytes:
        raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return self._ber_tlv(0x02, raw)

    def _ber_octet_string(self, value: str) -> bytes:
        return self._ber_tlv(0x04, value.encode("ascii", errors="ignore"))

    def _ber_oid(self, oid: tuple[int, ...]) -> bytes:
        if len(oid) < 2:
            raise ValueError("OID invalide")
        encoded = bytearray([oid[0] * 40 + oid[1]])
        for part in oid[2:]:
            stack = [part & 0x7F]
            part >>= 7
            while part:
                stack.append(0x80 | (part & 0x7F))
                part >>= 7
            encoded.extend(reversed(stack))
        return self._ber_tlv(0x06, bytes(encoded))

    def _extract_ber_strings(self, data: bytes) -> list[str]:
        strings: list[str] = []

        def read_length(offset: int) -> tuple[int, int]:
            first = data[offset]
            offset += 1
            if first < 128:
                return first, offset
            size = first & 0x7F
            if size == 0 or offset + size > len(data):
                raise ValueError("longueur BER invalide")
            return int.from_bytes(data[offset : offset + size], "big"), offset + size

        def walk(offset: int, end: int, depth: int = 0) -> None:
            if depth > 12:
                return
            while offset + 2 <= end and offset < len(data):
                tag = data[offset]
                offset += 1
                try:
                    length, value_offset = read_length(offset)
                except (IndexError, ValueError):
                    return
                value_end = value_offset + length
                if value_end > len(data):
                    return
                value = data[value_offset:value_end]
                if tag == 0x04:
                    text = value.decode(errors="ignore").strip()
                    printable = sum(1 for char in text if char.isprintable())
                    if len(text) > 1 and printable >= max(1, int(len(text) * 0.8)) and text not in strings:
                        strings.append(text[:300])
                if tag in {0x30, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4}:
                    walk(value_offset, value_end, depth + 1)
                offset = value_end

        walk(0, len(data))
        return strings

    def _fingerprint_service(self, port: int, banner: str | None) -> tuple[str | None, str | None, str | None]:
        if not banner:
            if port == 5985:
                return "Windows Remote Management", None, "Microsoft"
            if port == 5986:
                return "Windows Remote Management", None, "Microsoft"
            return None, None, None

        patterns = [
            (r"OpenSSH[_/](?P<version>[0-9A-Za-z\.\-p]+)", "OpenSSH", "OpenBSD"),
            (r"Apache/(?P<version>[0-9.]+)", "Apache HTTP Server", "Apache Software Foundation"),
            (r"nginx/(?P<version>[0-9.]+)", "nginx", "F5 NGINX"),
            (r"lighttpd/(?P<version>[0-9.]+)", "lighttpd", "lighttpd"),
            (r"MiniServ/(?P<version>[0-9.]+)", "Webmin", "Webmin"),
            (r"Microsoft-HTTPAPI/(?P<version>[0-9.]+)", "Microsoft HTTPAPI", "Microsoft"),
            (r"OpenSSL/(?P<version>[0-9A-Za-z\.\-]+)", "OpenSSL", "OpenSSL"),
        ]
        for pattern, product, vendor in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return product, match.group("version"), vendor

        lowered = banner.lower()
        if "synology" in lowered or "diskstation" in lowered:
            return "Synology DSM", None, "Synology"
        if "qnap" in lowered or " qts" in lowered or "quts" in lowered:
            return "QNAP QTS", None, "QNAP"
        if "server: nginx" in lowered:
            return "nginx", None, "F5 NGINX"
        if "server: apache" in lowered:
            return "Apache HTTP Server", None, "Apache Software Foundation"
        if "server: microsoft-iis" in lowered:
            version_match = re.search(r"microsoft-iis/(?P<version>[0-9.]+)", lowered)
            version = version_match.group("version") if version_match else None
            return "Microsoft IIS", version, "Microsoft"
        return None, None, None

    def _read_arp_neighbors(self, network: ipaddress._BaseNetwork) -> dict[str, str]:
        neighbors: dict[str, str] = {}
        for source in (self._read_arp_command_neighbors, self._read_windows_net_neighbors, self._read_unix_ip_neighbors):
            for ip, mac in source(network).items():
                neighbors.setdefault(ip, mac)
        return neighbors

    def _read_arp_command_neighbors(self, network: ipaddress._BaseNetwork) -> dict[str, str]:
        command = ["arp", "-a"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            return {}

        if result.returncode != 0:
            return {}

        neighbors: dict[str, str] = {}
        for line in result.stdout.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+(([0-9a-f]{2}-){5}[0-9a-f]{2}|([0-9a-f]{2}:){5}[0-9a-f]{2})", line.strip(), re.IGNORECASE)
            if not match:
                continue
            ip = match.group(1)
            mac = match.group(2)
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if address in network and address not in {network.network_address, network.broadcast_address}:
                neighbors[ip] = mac
        return neighbors

    def _read_windows_net_neighbors(self, network: ipaddress._BaseNetwork) -> dict[str, str]:
        if platform.system().lower() != "windows":
            return {}
        script = """
        Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notin @('00-00-00-00-00-00', 'ff-ff-ff-ff-ff-ff') } |
          Select-Object IPAddress, LinkLayerAddress, State |
          ConvertTo-Json -Depth 3
        """
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {}
        items = payload if isinstance(payload, list) else [payload]
        neighbors: dict[str, str] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            ip = item.get("IPAddress")
            mac = item.get("LinkLayerAddress")
            if self._address_in_network(ip, network) and mac:
                neighbors[str(ip)] = str(mac)
        return neighbors

    def _read_unix_ip_neighbors(self, network: ipaddress._BaseNetwork) -> dict[str, str]:
        if platform.system().lower() == "windows":
            return {}
        try:
            result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            return {}
        if result.returncode != 0:
            return {}
        neighbors: dict[str, str] = {}
        for line in result.stdout.splitlines():
            match = re.search(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*lladdr\s+(?P<mac>([0-9a-f]{2}:){5}[0-9a-f]{2})", line, re.IGNORECASE)
            if not match:
                continue
            ip = match.group("ip")
            if self._address_in_network(ip, network):
                neighbors[ip] = match.group("mac")
        return neighbors

    def _address_in_network(self, ip: object, network: ipaddress._BaseNetwork) -> bool:
        try:
            address = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        return address in network and address not in {network.network_address, network.broadcast_address}


def detect_local_network_cidr() -> str | None:
    command = ["ipconfig"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None

    ipv4 = None
    mask = None
    for line in result.stdout.splitlines():
        if "Adresse IPv4" in line or "IPv4 Address" in line:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                candidate = match.group(1)
                if ipaddress.ip_address(candidate).is_private:
                    ipv4 = candidate
        if "Masque de sous-r" in line or "Subnet Mask" in line:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                mask = match.group(1)
        if ipv4 and mask:
            network = ipaddress.IPv4Network(f"{ipv4}/{mask}", strict=False)
            return str(network)
    return None
