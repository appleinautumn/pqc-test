package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"
)

type probeResult struct {
	Success          bool   `json:"success"`
	ErrorKind        string `json:"error_kind,omitempty"`
	Error            string `json:"error,omitempty"`
	TLSVersion       string `json:"tls_version,omitempty"`
	CipherSuite      string `json:"cipher_suite,omitempty"`
	NegotiatedGroup  string `json:"negotiated_group,omitempty"`
	Backend          string `json:"backend"`
	BackendVersion   string `json:"backend_version"`
	CertificateValid *bool  `json:"certificate_verified"`
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

func probe(host string, port int, timeout time.Duration, curves []tls.CurveID) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	address := net.JoinHostPort(host, strconv.Itoa(port))
	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return resultWithError("network_error", err)
	}
	defer rawConn.Close()

	serverName := ""
	if net.ParseIP(host) == nil {
		serverName = host
	}

	conn := tls.Client(rawConn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   curves,
		ServerName:         serverName,
		InsecureSkipVerify: true, // Capability probe only; certificate validity is not evaluated.
	})
	defer conn.Close()

	if err := conn.HandshakeContext(ctx); err != nil {
		return resultWithError("tls_handshake_failed", err)
	}

	state := conn.ConnectionState()
	return probeResult{
		Success:          true,
		TLSVersion:       tlsVersionName(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		NegotiatedGroup:  curveName(state.CurveID),
		Backend:          "go-crypto-tls",
		BackendVersion:   runtime.Version(),
		CertificateValid: nil,
	}
}

func main() {
	host := flag.String("host", "", "target hostname or IP address")
	port := flag.Int("port", 443, "target TLS port")
	timeoutSeconds := flag.Float64("timeout", 10, "network timeout in seconds")
	group := flag.String("group", "x25519mlkem768", "group set: x25519mlkem768 or classical")
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

	result := probe(*host, *port, time.Duration(*timeoutSeconds*float64(time.Second)), curves)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
