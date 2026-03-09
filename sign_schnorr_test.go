package main

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestSchnorSign(t *testing.T) {
	curve := elliptic.P256()
	ellipticCurve := NewECCurve(curve)

	privKey, pubKey, err := ellipticCurve.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	message := new(big.Int).SetBytes([]byte("Hello, Schnorr!"))

	signature, err := ellipticCurve.Sign(message, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	verified := ellipticCurve.Verify(signature, message, pubKey)
	if !verified {
		t.Fatal("signature is invalid.")
	}
}

func TestSchnorrVerifyWithNilPubKey(t *testing.T) {
	curve := elliptic.P256()
	ellipticCurve := NewECCurve(curve)

	privKey, _, err := ellipticCurve.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	message := new(big.Int).SetBytes([]byte("test"))

	signature, err := ellipticCurve.Sign(message, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if ellipticCurve.Verify(signature, message, ECPoint{}) {
		t.Fatal("verification should fail with empty public key")
	}
}

func TestSchnorrVerifyWithInvalidSignature(t *testing.T) {
	curve := elliptic.P256()
	ellipticCurve := NewECCurve(curve)

	_, pubKey, err := ellipticCurve.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	message := new(big.Int).SetBytes([]byte("test"))
	invalidSig := &SchnorrSignature{R: big.NewInt(1), S: big.NewInt(1)}

	if ellipticCurve.Verify(invalidSig, message, pubKey) {
		t.Fatal("verification should fail with invalid signature")
	}
}

func TestSchnorrVerifyWithWrongMessage(t *testing.T) {
	curve := elliptic.P256()
	ellipticCurve := NewECCurve(curve)

	privKey, pubKey, err := ellipticCurve.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	message := new(big.Int).SetBytes([]byte("original message"))

	signature, err := ellipticCurve.Sign(message, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	wrongMessage := new(big.Int).SetBytes([]byte("different message"))
	if ellipticCurve.Verify(signature, wrongMessage, pubKey) {
		t.Fatal("verification should fail with wrong message")
	}
}

func TestSchnorrVerifyWithWrongPubKey(t *testing.T) {
	curve := elliptic.P256()
	ellipticCurve := NewECCurve(curve)

	privKey, _, err := ellipticCurve.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	_, wrongPubKey, err := ellipticCurve.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate wrong key pair: %v", err)
	}

	message := new(big.Int).SetBytes([]byte("test"))

	signature, err := ellipticCurve.Sign(message, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if ellipticCurve.Verify(signature, message, wrongPubKey) {
		t.Fatal("verification should fail with wrong public key")
	}
}

func TestSchnorrVerifyWithNilSignature(t *testing.T) {
	curve := elliptic.P256()
	ellipticCurve := NewECCurve(curve)

	_, pubKey, err := ellipticCurve.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	message := new(big.Int).SetBytes([]byte("test"))

	if ellipticCurve.Verify(nil, message, pubKey) {
		t.Fatal("verification should fail with nil signature")
	}
}
