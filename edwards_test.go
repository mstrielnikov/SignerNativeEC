package main

import (
	"math/big"
	"testing"
)

func TestEdwardsSchnorrSign(t *testing.T) {
	// Simple Twisted Edwards curve parameters for testing
	// a = -1, d = 3, p = 17 (d is a non-residue mod 17)
	// Equation: -x^2 + y^2 = 1 + 3x^2y^2 (mod 17)
	a := big.NewInt(-1)
	d := big.NewInt(3)
	p := big.NewInt(17)
	n := big.NewInt(16) // Group order (example)
	Gx := big.NewInt(1)
	Gy := big.NewInt(4)

	edCurve := NewEdwardsCurve(a, d, p, n, Gx, Gy)
	wrapper := NewECCurve(edCurve)

	priv, pub, err := wrapper.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	message := big.NewInt(42)
	sig, err := wrapper.Sign(message, priv)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if !wrapper.Verify(sig, message, pub) {
		t.Fatal("Edwards Schnorr verification failed")
	}
}
