#!/usr/bin/env python3
import argparse
import ipaddress
import json
import re
import subprocess
from urllib.parse import urlsplit

# Standard NIST PQC and draft hybrid groups
PQC_GROUPS = {
    "X25519MLKEM768",      # NIST FIPS 203 Standard
    "SecP256r1MLKEM768",   # FIPS-compliant hybrid
    "X25519Kyber768Draft00"# Legacy pre-standard draft
}


class TargetError(ValueError):
    """Raised when a probe target cannot be parsed safely."""


def validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise TargetError("port must be between 1 and 65535")
    return port


def normalize_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise TargetError("target host cannot be empty")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        normalized = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetError(f"invalid target host: {host!r}") from exc

    dns_name = normalized.removesuffix(".")
    if not dns_name or len(dns_name) > 253:
        raise TargetError(f"invalid target host: {host!r}")
    if any(not label or len(label) > 63 for label in dns_name.split(".")):
        raise TargetError(f"invalid target host: {host!r}")
    if any(not re.fullmatch(r"[a-z0-9-]+", label) for label in dns_name.split(".")):
        raise TargetError(f"invalid target host: {host!r}")

    return normalized


def parse_target(target: str, explicit_port: int | None = None) -> tuple[str, int]:
    """Parse a hostname, IP address, host:port pair, or HTTPS URL."""
    target = target.strip()
    if not target:
        raise TargetError("target cannot be empty")

    embedded_port = None
    if "://" in target:
        parsed = urlsplit(target)
        if parsed.scheme.lower() != "https":
            raise TargetError("only HTTPS URLs are supported")
        if parsed.username is not None or parsed.password is not None:
            raise TargetError("target URLs must not contain credentials")
        host = parsed.hostname
        try:
            embedded_port = parsed.port
        except ValueError as exc:
            raise TargetError("target contains an invalid port") from exc
    else:
        if any(character in target for character in "/?#"):
            raise TargetError("use an HTTPS URL when specifying a path, query, or fragment")

        try:
            host = str(ipaddress.ip_address(target))
        except ValueError:
            parsed = urlsplit(f"//{target}")
            if parsed.username is not None or parsed.password is not None:
                raise TargetError("target must not contain credentials")
            host = parsed.hostname
            try:
                embedded_port = parsed.port
            except ValueError as exc:
                raise TargetError("target contains an invalid port") from exc

    if host is None:
        raise TargetError("target does not contain a host")

    port = explicit_port if explicit_port is not None else embedded_port or 443
    return normalize_host(host), validate_port(port)


def format_connect_target(host: str, port: int) -> str:
    """Format a host and port for OpenSSL's -connect argument."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{port}"
    if address.version == 6:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def check_pqc_readiness(host: str, port: int = 443, timeout: float = 10) -> dict:
    """
    Probes a remote server by offering hybrid PQC groups in TLS 1.3 ClientHello.
    Requires OpenSSL 3.5+ or OpenSSL built with oqs-provider.
    """
    host = normalize_host(host)
    port = validate_port(port)
    if timeout <= 0:
        raise TargetError("timeout must be greater than zero")

    cmd = [
        "openssl", "s_client",
        "-connect", format_connect_target(host, port),
    ]
    if not is_ip_address(host):
        cmd.extend(["-servername", host])
    cmd.extend([
        "-tls1_3",
        "-groups", "X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256"
    ])

    try:
        proc = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        output = proc.stdout.decode("utf-8", errors="ignore")
    except FileNotFoundError:
        return {"error": "OpenSSL binary not found in system PATH."}
    except subprocess.TimeoutExpired:
        return {"error": f"Connection timed out when probing {host}:{port}."}

    # Extract TLS Protocol
    protocol_match = re.search(r"Protocol\s*:\s*(TLSv[\d\.]+)", output)
    protocol = protocol_match.group(1) if protocol_match else "Unknown"

    # Extract Cipher Suite
    cipher_match = re.search(r"Cipher\s*:\s*([A-Za-z0-9_\-]+)", output)
    cipher = cipher_match.group(1) if cipher_match else "Unknown"

    # Extract Negotiated TLS 1.3 Named Group (Key Exchange)
    group_match = re.search(r"Negotiated TLS1\.3 group\s*:\s*([A-Za-z0-9_\-]+)", output)
    group = group_match.group(1) if group_match else None

    # Check PQC Status
    if group and any(pqc in group for pqc in PQC_GROUPS):
        pqc_status = "PQC_SECURE_HYBRID"
        is_pqc = True
        status_label = "aman"
    elif group:
        pqc_status = "CLASSICAL_ONLY"
        is_pqc = False
        status_label = "belum aman (vulnerable to HNDL)"
    else:
        pqc_status = "HANDSHAKE_FAILED_OR_LEGACY"
        is_pqc = False
        status_label = "incompatible"

    return {
        "target": host,
        "port": port,
        "pqc_status": pqc_status,
        "is_quantum_resistant": is_pqc,
        "evaluation": status_label,
        "details": {
            "protocol": protocol,
            "cipher_suite": cipher,
            "negotiated_group": group or "None negotiated"
        }
    }

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Probe an HTTPS endpoint for hybrid post-quantum TLS support."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="cloudflare.com",
        help="hostname, IP address, host:port pair, or HTTPS URL",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="TLS port (overrides a port included in the target; default: 443)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=10.0,
        help="connection timeout in seconds (default: 10)",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    try:
        host, port = parse_target(args.target, args.port)
        result = check_pqc_readiness(host, port, args.timeout)
    except TargetError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
