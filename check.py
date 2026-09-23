#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

TARGET_GROUP = "X25519MLKEM768"
GO_PROBE = Path(__file__).with_name("pqc_probe.go")


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


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def run_go_probe(
    host: str,
    port: int,
    timeout: float,
    group: str,
    verify_certificate: bool = False,
) -> dict:
    """Run the Go TLS backend and return its structured probe result."""
    command = [
        "go",
        "run",
        str(GO_PROBE),
        "--host",
        host,
        "--port",
        str(port),
        "--timeout",
        str(timeout),
        "--group",
        group,
    ]
    if verify_certificate:
        command.append("--verify-certificate")
    environment = os.environ.copy()
    environment.setdefault("GOCACHE", str(Path(tempfile.gettempdir()) / "pqc-go-cache"))
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
            check=False,
            env=environment,
        )
    except FileNotFoundError:
        return {
            "success": False,
            "error_kind": "local_backend_unavailable",
            "error": "Go is not installed or is not available in PATH.",
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error_kind": "local_backend_timeout",
            "error": "The Go probe did not finish in time.",
        }

    if process.returncode != 0:
        error = process.stderr.strip() or "The Go probe exited without a result."
        return {
            "success": False,
            "error_kind": "local_backend_error",
            "error": error,
        }

    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError:
        return {
            "success": False,
            "error_kind": "local_backend_error",
            "error": "The Go probe returned invalid JSON.",
        }
    if not isinstance(result, dict):
        return {
            "success": False,
            "error_kind": "local_backend_error",
            "error": "The Go probe returned an unexpected result.",
        }
    return result


def summarize_certificate_chain(certificates: object) -> dict:
    """Summarize algorithm classifications for the server-presented chain."""
    if not isinstance(certificates, list) or not certificates:
        return {
            "status": "unavailable",
            "presented_chain_classification": "unknown",
            "certificates": [],
        }

    classifications = []
    for certificate in certificates:
        if not isinstance(certificate, dict):
            classifications.append("unknown")
            continue
        classifications.extend(
            [
                certificate.get("public_key_classification", "unknown"),
                certificate.get("signature_classification", "unknown"),
            ]
        )

    known_classifications = {"classical", "post_quantum", "hybrid"}
    if any(item not in known_classifications for item in classifications):
        chain_classification = "unknown"
    elif len(set(classifications)) == 1:
        chain_classification = classifications[0]
    else:
        chain_classification = "mixed"

    return {
        "status": "classified",
        "presented_chain_classification": chain_classification,
        "certificates": certificates,
    }


def check_pqc_readiness(
    host: str,
    port: int = 443,
    timeout: float = 10,
    verify_certificate: bool = False,
) -> dict:
    """Test X25519MLKEM768 support and optionally verify the certificate."""
    host = normalize_host(host)
    port = validate_port(port)
    if timeout <= 0:
        raise TargetError("timeout must be greater than zero")

    pqc_probe = run_go_probe(host, port, timeout, "x25519mlkem768")
    classical_probe = None

    if pqc_probe.get("success") and pqc_probe.get("negotiated_group") == TARGET_GROUP:
        status = "X25519MLKEM768_NEGOTIATED"
        supports_group = True
        key_establishment_security = "hybrid_post_quantum"
        evaluation = "The endpoint negotiated hybrid X25519MLKEM768 key exchange."
    elif pqc_probe.get("error_kind") == "tls_handshake_failed":
        classical_probe = run_go_probe(host, port, timeout, "classical")
        if classical_probe.get("success"):
            status = "X25519MLKEM768_NOT_SUPPORTED"
            supports_group = False
            key_establishment_security = "target_hybrid_group_not_supported"
            evaluation = "TLS 1.3 works, but the endpoint did not accept X25519MLKEM768."
        else:
            status = "INCONCLUSIVE"
            supports_group = None
            key_establishment_security = "unknown"
            evaluation = "Neither the hybrid-group probe nor the classical control completed a TLS handshake."
    elif pqc_probe.get("error_kind") == "network_error":
        status = "NETWORK_ERROR"
        supports_group = None
        key_establishment_security = "unknown"
        evaluation = "The endpoint could not be reached, so X25519MLKEM768 support is unknown."
    else:
        status = "LOCAL_PROBE_ERROR"
        supports_group = None
        key_establishment_security = "unknown"
        evaluation = "The local Go TLS probe could not perform the test."

    certificate_probe = pqc_probe if pqc_probe.get("success") else classical_probe
    certificate_analysis = summarize_certificate_chain(
        certificate_probe.get("certificates") if certificate_probe else None
    )

    verification_probe = None
    if not verify_certificate:
        certificate_verification = {
            "requested": False,
            "status": "not_requested",
            "verified": None,
            "hostname_verified": None,
            "error": None,
        }
    elif supports_group is None:
        certificate_verification = {
            "requested": True,
            "status": "unavailable",
            "verified": None,
            "hostname_verified": None,
            "error": "No successful TLS handshake was available for certificate verification.",
        }
    else:
        verification_group = "x25519mlkem768" if supports_group else "classical"
        verification_probe = run_go_probe(
            host,
            port,
            timeout,
            verification_group,
            verify_certificate=True,
        )
        certificate_verified = verification_probe.get("certificate_verified")
        if verification_probe.get("success") and certificate_verified is True:
            verification_status = "verified"
        elif verification_probe.get("error_kind") == "certificate_verification_failed":
            verification_status = "failed"
        else:
            verification_status = "unavailable"
        certificate_verification = {
            "requested": True,
            "status": verification_status,
            "verified": certificate_verified,
            "hostname_verified": verification_probe.get("hostname_verified"),
            "error": verification_probe.get("error"),
        }

    return {
        "target": host,
        "port": port,
        "pqc_status": status,
        "supports_x25519_mlkem768": supports_group,
        "key_establishment_security": key_establishment_security,
        "certificate_security": certificate_analysis["presented_chain_classification"],
        "certificate_analysis": certificate_analysis,
        "certificate_verification": certificate_verification,
        "is_quantum_resistant": supports_group,
        "evaluation": evaluation,
        "details": {
            "protocol": pqc_probe.get("tls_version", "Unknown"),
            "cipher_suite": pqc_probe.get("cipher_suite", "Unknown"),
            "negotiated_group": pqc_probe.get("negotiated_group", "None negotiated"),
            "certificate_verified": certificate_verification["verified"],
            "backend": pqc_probe.get("backend", "go-crypto-tls"),
            "backend_version": pqc_probe.get("backend_version", "Unknown"),
            "error": pqc_probe.get("error"),
        },
        "probes": {
            "x25519_mlkem768": pqc_probe,
            "classical_control": classical_probe,
            "certificate_verification": verification_probe,
        },
        "limitations": [
            "Certificate algorithm classification covers only certificates presented by the server.",
            "Algorithm classification does not establish certificate validity; use --verify-certificate.",
            "is_quantum_resistant is deprecated; use the dimension-specific result fields.",
            "Other IP addresses or CDN regions may negotiate differently.",
        ],
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
    parser.add_argument(
        "--verify-certificate",
        action="store_true",
        help="verify the certificate chain and target hostname in a separate handshake",
    )
    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    try:
        host, port = parse_target(args.target, args.port)
        result = check_pqc_readiness(
            host,
            port,
            args.timeout,
            verify_certificate=args.verify_certificate,
        )
    except TargetError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
