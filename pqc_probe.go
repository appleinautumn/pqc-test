package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type certificateInfo struct {
	Index                   int    `json:"index"`
	Role                    string `json:"role"`
	Subject                 string `json:"subject"`
	Issuer                  string `json:"issuer"`
	PublicKeyAlgorithm      string `json:"public_key_algorithm"`
	PublicKeyClassification string `json:"public_key_classification"`
	SignatureAlgorithm      string `json:"signature_algorithm"`
	SignatureClassification string `json:"signature_classification"`
}

type probeResult struct {
	Success          bool              `json:"success"`
	ErrorKind        string            `json:"error_kind,omitempty"`
	Error            string            `json:"error,omitempty"`
	TLSVersion       string            `json:"tls_version,omitempty"`
	CipherSuite      string            `json:"cipher_suite,omitempty"`
	NegotiatedGroup  string            `json:"negotiated_group,omitempty"`
	Backend          string            `json:"backend"`
	BackendVersion   string            `json:"backend_version"`
	CertificateValid *bool             `json:"certificate_verified"`
	HostnameValid    *bool             `json:"hostname_verified"`
	Certificates     []certificateInfo `json:"certificates,omitempty"`
}

func curveName(curve tls.CurveID) string {
	switch curve {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.SecP256r1MLKEM768:
		return "SecP256r1MLKEM768"
	case tls.SecP384r1MLKEM1024:
		return "SecP384r1MLKEM1024"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	default:
		return fmt.Sprintf("CurveID(%d)", curve)
	}
}

func classifyAlgorithmName(name string) string {
	normalized := strings.ToUpper(name)
	postQuantum := strings.Contains(normalized, "ML-DSA") ||
		strings.Contains(normalized, "MLDSA") ||
		strings.Contains(normalized, "SLH-DSA") ||
		strings.Contains(normalized, "SLHDSA") ||
		strings.Contains(normalized, "DILITHIUM") ||
		strings.Contains(normalized, "FALCON") ||
		strings.Contains(normalized, "SPHINCS")
	classical := strings.Contains(normalized, "RSA") ||
		strings.Contains(normalized, "ECDSA") ||
		strings.Contains(normalized, "ED25519")

	switch {
	case strings.Contains(normalized, "HYBRID") || strings.Contains(normalized, "COMPOSITE"):
		return "hybrid"
	case postQuantum && classical:
		return "hybrid"
	case postQuantum:
		return "post_quantum"
	default:
		return "unknown"
	}
}

func classifyPublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm) string {
	switch algorithm {
	case x509.RSA, x509.DSA, x509.ECDSA, x509.Ed25519:
		return "classical"
	default:
		return classifyAlgorithmName(algorithm.String())
	}
}

func classifySignatureAlgorithm(algorithm x509.SignatureAlgorithm) string {
	switch algorithm {
	case x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.DSAWithSHA1,
		x509.DSAWithSHA256,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS,
		x509.PureEd25519:
		return "classical"
	default:
		return classifyAlgorithmName(algorithm.String())
	}
}

func certificateInfos(certificates []*x509.Certificate) []certificateInfo {
	infos := make([]certificateInfo, 0, len(certificates))
	for index, certificate := range certificates {
		role := "chain"
		if index == 0 {
			role = "leaf"
		}
		infos = append(infos, certificateInfo{
			Index:                   index,
			Role:                    role,
			Subject:                 certificate.Subject.String(),
			Issuer:                  certificate.Issuer.String(),
			PublicKeyAlgorithm:      certificate.PublicKeyAlgorithm.String(),
			PublicKeyClassification: classifyPublicKeyAlgorithm(certificate.PublicKeyAlgorithm),
			SignatureAlgorithm:      certificate.SignatureAlgorithm.String(),
			SignatureClassification: classifySignatureAlgorithm(certificate.SignatureAlgorithm),
		})
	}
	return infos
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func resultWithError(kind string, err error) probeResult {
	return probeResult{
		ErrorKind:      kind,
		Error:          err.Error(),
		Backend:        "go-crypto-tls",
		BackendVersion: runtime.Version(),
	}
}

func probe(host string, port int, timeout time.Duration, curves []tls.CurveID, verifyCertificate bool) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	address := net.JoinHostPort(host, strconv.Itoa(port))
	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return resultWithError("network_error", err)
	}
	defer rawConn.Close()

	serverName := ""
	if verifyCertificate || net.ParseIP(host) == nil {
		serverName = host
	}

	conn := tls.Client(rawConn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   curves,
		ServerName:         serverName,
		InsecureSkipVerify: !verifyCertificate,
	})
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		result := resultWithError("tls_handshake_failed", err)
		var verificationError *tls.CertificateVerificationError
		if verifyCertificate && errors.As(err, &verificationError) {
			certificateValid := false
			result.ErrorKind = "certificate_verification_failed"
			result.CertificateValid = &certificateValid
			if len(verificationError.UnverifiedCertificates) > 0 {
				hostnameValid := verificationError.UnverifiedCertificates[0].VerifyHostname(host) == nil
				result.HostnameValid = &hostnameValid
				result.Certificates = certificateInfos(verificationError.UnverifiedCertificates)
			}
		}
		return result
	}

	state := conn.ConnectionState()
	var certificateValid *bool
	var hostnameValid *bool
	if verifyCertificate {
		verified := true
		certificateValid = &verified
		hostnameValid = &verified
	}
	return probeResult{
		Success:          true,
		TLSVersion:       tlsVersionName(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		NegotiatedGroup:  curveName(state.CurveID),
		Backend:          "go-crypto-tls",
		BackendVersion:   runtime.Version(),
		CertificateValid: certificateValid,
		HostnameValid:    hostnameValid,
		Certificates:     certificateInfos(state.PeerCertificates),
	}
}

func main() {
	host := flag.String("host", "", "target hostname or IP address")
	port := flag.Int("port", 443, "target TLS port")
	timeoutSeconds := flag.Float64("timeout", 10, "network timeout in seconds")
	group := flag.String("group", "x25519mlkem768", "group set: x25519mlkem768 or classical")
	verifyCertificate := flag.Bool("verify-certificate", false, "verify the certificate chain and target hostname")
	flag.Parse()

	if *host == "" || *port < 1 || *port > 65535 || *timeoutSeconds <= 0 {
		fmt.Fprintln(os.Stderr, "invalid host, port, or timeout")
		os.Exit(2)
	}

	var curves []tls.CurveID
	switch *group {
	case "x25519mlkem768":
		curves = []tls.CurveID{tls.X25519MLKEM768}
	case "classical":
		curves = []tls.CurveID{tls.X25519, tls.CurveP256}
	default:
		fmt.Fprintln(os.Stderr, "unsupported group set")
		os.Exit(2)
	}

	result := probe(*host, *port, time.Duration(*timeoutSeconds*float64(time.Second)), curves, *verifyCertificate)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
