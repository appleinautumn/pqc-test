import json
import subprocess
import unittest
from unittest.mock import patch

import check


class ParseTargetTests(unittest.TestCase):
    def test_hostname_uses_default_port(self):
        self.assertEqual(check.parse_target("Example.COM"), ("example.com", 443))

    def test_hostname_with_port(self):
        self.assertEqual(check.parse_target("example.com:8443"), ("example.com", 8443))

    def test_https_url_extracts_host_and_port(self):
        self.assertEqual(
            check.parse_target("https://Example.COM:9443/some/path?query=yes"),
            ("example.com", 9443),
        )

    def test_explicit_port_overrides_embedded_port(self):
        self.assertEqual(
            check.parse_target("https://example.com:9443", 443),
            ("example.com", 443),
        )

    def test_unicode_hostname_is_converted_to_idna(self):
        self.assertEqual(check.parse_target("bücher.example"), ("xn--bcher-kva.example", 443))

    def test_ipv4_address(self):
        self.assertEqual(check.parse_target("192.0.2.1"), ("192.0.2.1", 443))

    def test_bare_ipv6_address(self):
        self.assertEqual(check.parse_target("2001:db8::1"), ("2001:db8::1", 443))

    def test_bracketed_ipv6_with_port(self):
        self.assertEqual(check.parse_target("[2001:db8::1]:8443"), ("2001:db8::1", 8443))

    def test_rejects_non_https_url(self):
        with self.assertRaisesRegex(check.TargetError, "only HTTPS"):
            check.parse_target("http://example.com")

    def test_rejects_credentials(self):
        with self.assertRaisesRegex(check.TargetError, "credentials"):
            check.parse_target("https://user:secret@example.com")

    def test_rejects_invalid_port(self):
        with self.assertRaisesRegex(check.TargetError, "between 1 and 65535"):
            check.parse_target("example.com", 70000)

    def test_rejects_path_without_url(self):
        with self.assertRaisesRegex(check.TargetError, "use an HTTPS URL"):
            check.parse_target("example.com/path")


class GoBackendTests(unittest.TestCase):
    @patch("check.subprocess.run")
    def test_run_go_probe_passes_normalized_arguments(self, run):
        backend_result = {
            "success": True,
            "negotiated_group": "X25519MLKEM768",
            "backend": "go-crypto-tls",
        }
        run.return_value = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(backend_result), stderr=""
        )

        result = check.run_go_probe("example.com", 8443, 2.5, "x25519mlkem768")

        self.assertEqual(result, backend_result)
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["go", "run"])
        self.assertEqual(command[command.index("--host") + 1], "example.com")
        self.assertEqual(command[command.index("--port") + 1], "8443")
        self.assertEqual(command[command.index("--group") + 1], "x25519mlkem768")
        self.assertEqual(run.call_args.kwargs["timeout"], 32.5)
        self.assertNotIn("--verify-certificate", command)

    @patch("check.subprocess.run")
    def test_run_go_probe_can_enable_certificate_verification(self, run):
        run.return_value = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({"success": True}), stderr=""
        )

        check.run_go_probe(
            "example.com",
            443,
            10,
            "x25519mlkem768",
            verify_certificate=True,
        )

        self.assertIn("--verify-certificate", run.call_args.args[0])

    @patch("check.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_go_is_reported_as_local_error(self, _run):
        result = check.run_go_probe("example.com", 443, 10, "x25519mlkem768")

        self.assertEqual(result["error_kind"], "local_backend_unavailable")


class CertificateClassificationTests(unittest.TestCase):
    def test_classifies_uniform_classical_chain(self):
        analysis = check.summarize_certificate_chain(
            [
                {
                    "public_key_classification": "classical",
                    "signature_classification": "classical",
                },
                {
                    "public_key_classification": "classical",
                    "signature_classification": "classical",
                },
            ]
        )

        self.assertEqual(analysis["status"], "classified")
        self.assertEqual(analysis["presented_chain_classification"], "classical")

    def test_classifies_mixed_chain(self):
        analysis = check.summarize_certificate_chain(
            [
                {
                    "public_key_classification": "post_quantum",
                    "signature_classification": "post_quantum",
                },
                {
                    "public_key_classification": "classical",
                    "signature_classification": "classical",
                },
            ]
        )

        self.assertEqual(analysis["presented_chain_classification"], "mixed")

    def test_unknown_algorithm_makes_chain_unknown(self):
        analysis = check.summarize_certificate_chain(
            [
                {
                    "public_key_classification": "unknown",
                    "signature_classification": "classical",
                }
            ]
        )

        self.assertEqual(analysis["presented_chain_classification"], "unknown")

    def test_missing_chain_is_unavailable(self):
        analysis = check.summarize_certificate_chain(None)

        self.assertEqual(analysis["status"], "unavailable")
        self.assertEqual(analysis["presented_chain_classification"], "unknown")


class PQCDetectionTests(unittest.TestCase):
    @patch("check.run_go_probe")
    def test_reports_x25519_mlkem768_negotiation(self, probe):
        probe.return_value = {
            "success": True,
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "negotiated_group": "X25519MLKEM768",
            "backend": "go-crypto-tls",
            "backend_version": "go1.26.4",
            "certificate_verified": None,
            "certificates": [
                {
                    "index": 0,
                    "role": "leaf",
                    "subject": "CN=example.com",
                    "issuer": "CN=Example CA",
                    "public_key_algorithm": "ECDSA",
                    "public_key_classification": "classical",
                    "signature_algorithm": "ECDSA-SHA256",
                    "signature_classification": "classical",
                }
            ],
        }

        result = check.check_pqc_readiness("Example.COM")

        self.assertEqual(result["pqc_status"], "X25519MLKEM768_NEGOTIATED")
        self.assertTrue(result["supports_x25519_mlkem768"])
        self.assertEqual(result["key_establishment_security"], "hybrid_post_quantum")
        self.assertEqual(result["certificate_security"], "classical")
        self.assertEqual(
            result["certificate_analysis"]["presented_chain_classification"],
            "classical",
        )
        self.assertEqual(
            result["certificate_verification"],
            {
                "requested": False,
                "status": "not_requested",
                "verified": None,
                "hostname_verified": None,
                "error": None,
            },
        )
        self.assertTrue(result["is_quantum_resistant"])
        probe.assert_called_once_with("example.com", 443, 10, "x25519mlkem768")

    @patch("check.run_go_probe")
    def test_classical_control_confirms_group_is_not_supported(self, probe):
        probe.side_effect = [
            {
                "success": False,
                "error_kind": "tls_handshake_failed",
                "error": "remote error: tls: handshake failure",
            },
            {
                "success": True,
                "tls_version": "TLSv1.3",
                "negotiated_group": "X25519",
            },
        ]

        result = check.check_pqc_readiness("example.com")

        self.assertEqual(result["pqc_status"], "X25519MLKEM768_NOT_SUPPORTED")
        self.assertFalse(result["supports_x25519_mlkem768"])
        self.assertEqual(
            result["key_establishment_security"],
            "target_hybrid_group_not_supported",
        )
        self.assertEqual(result["certificate_security"], "unknown")
        self.assertFalse(result["is_quantum_resistant"])
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(probe.call_args_list[1].args[3], "classical")

    @patch("check.run_go_probe")
    def test_failed_pqc_and_control_probes_are_inconclusive(self, probe):
        probe.side_effect = [
            {"success": False, "error_kind": "tls_handshake_failed"},
            {"success": False, "error_kind": "tls_handshake_failed"},
        ]

        result = check.check_pqc_readiness("example.com")

        self.assertEqual(result["pqc_status"], "INCONCLUSIVE")
        self.assertIsNone(result["supports_x25519_mlkem768"])
        self.assertEqual(result["key_establishment_security"], "unknown")
        self.assertEqual(result["certificate_security"], "unknown")
        self.assertIsNone(result["is_quantum_resistant"])

    @patch("check.run_go_probe")
    def test_network_error_does_not_claim_no_pqc_support(self, probe):
        probe.return_value = {
            "success": False,
            "error_kind": "network_error",
            "error": "connection refused",
        }

        result = check.check_pqc_readiness("example.com")

        self.assertEqual(result["pqc_status"], "NETWORK_ERROR")
        self.assertIsNone(result["supports_x25519_mlkem768"])
        self.assertEqual(result["key_establishment_security"], "unknown")
        self.assertEqual(result["certificate_security"], "unknown")
        self.assertIsNone(result["is_quantum_resistant"])
        probe.assert_called_once()

    @patch("check.run_go_probe")
    def test_optional_certificate_verification_succeeds(self, probe):
        probe.side_effect = [
            {
                "success": True,
                "tls_version": "TLSv1.3",
                "negotiated_group": "X25519MLKEM768",
            },
            {
                "success": True,
                "certificate_verified": True,
                "hostname_verified": True,
            },
        ]

        result = check.check_pqc_readiness(
            "example.com",
            verify_certificate=True,
        )

        self.assertTrue(result["supports_x25519_mlkem768"])
        self.assertEqual(result["certificate_verification"]["status"], "verified")
        self.assertTrue(result["certificate_verification"]["verified"])
        self.assertTrue(result["certificate_verification"]["hostname_verified"])
        probe.assert_called_with(
            "example.com",
            443,
            10,
            "x25519mlkem768",
            verify_certificate=True,
        )

    @patch("check.run_go_probe")
    def test_certificate_failure_preserves_key_establishment_result(self, probe):
        probe.side_effect = [
            {
                "success": True,
                "tls_version": "TLSv1.3",
                "negotiated_group": "X25519MLKEM768",
            },
            {
                "success": False,
                "error_kind": "certificate_verification_failed",
                "certificate_verified": False,
                "hostname_verified": True,
                "error": "x509: certificate signed by unknown authority",
            },
        ]

        result = check.check_pqc_readiness(
            "example.com",
            verify_certificate=True,
        )

        self.assertTrue(result["supports_x25519_mlkem768"])
        self.assertEqual(result["key_establishment_security"], "hybrid_post_quantum")
        self.assertEqual(result["certificate_verification"]["status"], "failed")
        self.assertFalse(result["certificate_verification"]["verified"])
        self.assertTrue(result["certificate_verification"]["hostname_verified"])

    @patch("check.run_go_probe")
    def test_certificate_verification_uses_successful_classical_control(self, probe):
        probe.side_effect = [
            {"success": False, "error_kind": "tls_handshake_failed"},
            {"success": True, "negotiated_group": "X25519"},
            {
                "success": True,
                "certificate_verified": True,
                "hostname_verified": True,
            },
        ]

        result = check.check_pqc_readiness(
            "example.com",
            verify_certificate=True,
        )

        self.assertFalse(result["supports_x25519_mlkem768"])
        self.assertEqual(result["certificate_verification"]["status"], "verified")
        self.assertEqual(probe.call_args.args[3], "classical")
        self.assertTrue(probe.call_args.kwargs["verify_certificate"])

    @patch("check.run_go_probe")
    def test_unavailable_handshake_cannot_verify_certificate(self, probe):
        probe.return_value = {
            "success": False,
            "error_kind": "network_error",
            "error": "connection refused",
        }

        result = check.check_pqc_readiness(
            "example.com",
            verify_certificate=True,
        )

        self.assertEqual(result["certificate_verification"]["status"], "unavailable")
        self.assertIsNone(result["certificate_verification"]["verified"])
        probe.assert_called_once()

    @patch("check.run_go_probe")
    def test_local_probe_error_has_unknown_security_semantics(self, probe):
        probe.return_value = {
            "success": False,
            "error_kind": "local_backend_error",
            "error": "The Go probe returned invalid JSON.",
        }

        result = check.check_pqc_readiness("example.com")

        self.assertEqual(result["pqc_status"], "LOCAL_PROBE_ERROR")
        self.assertIsNone(result["supports_x25519_mlkem768"])
        self.assertEqual(result["key_establishment_security"], "unknown")
        self.assertEqual(result["certificate_security"], "unknown")
        self.assertIsNone(result["is_quantum_resistant"])
        probe.assert_called_once()


if __name__ == "__main__":
    unittest.main()
