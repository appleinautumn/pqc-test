package main

import (
	"crypto/x509"
	"testing"
)

func TestClassifyKnownClassicalAlgorithms(t *testing.T) {
	if got := classifyPublicKeyAlgorithm(x509.ECDSA); got != "classical" {
		t.Fatalf("classifyPublicKeyAlgorithm(ECDSA) = %q, want classical", got)
	}
	if got := classifySignatureAlgorithm(x509.SHA256WithRSA); got != "classical" {
		t.Fatalf("classifySignatureAlgorithm(SHA256WithRSA) = %q, want classical", got)
	}
}

func TestClassifyPostQuantumAlgorithmName(t *testing.T) {
	if got := classifyAlgorithmName("ML-DSA-65"); got != "post_quantum" {
		t.Fatalf("classifyAlgorithmName(ML-DSA-65) = %q, want post_quantum", got)
	}
}

func TestClassifyHybridAlgorithmName(t *testing.T) {
	if got := classifyAlgorithmName("ML-DSA-65+ECDSA-P256"); got != "hybrid" {
		t.Fatalf("classifyAlgorithmName(hybrid) = %q, want hybrid", got)
	}
}

func TestUnknownAlgorithmIsNotGuessed(t *testing.T) {
	unknown := x509.PublicKeyAlgorithm(999)
	if got := classifyPublicKeyAlgorithm(unknown); got != "unknown" {
		t.Fatalf("classifyPublicKeyAlgorithm(999) = %q, want unknown", got)
	}
}
