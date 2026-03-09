package main

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestSchnorrAggregationWeierstrass(t *testing.T) {
	curve := NewECCurve(elliptic.P256())
	runAggregationTest(t, curve)
}

func TestSchnorrAggregationEdwards(t *testing.T) {
	// Simple Twisted Edwards curve
	a := big.NewInt(-1)
	d := big.NewInt(3)
	p := big.NewInt(17)
	n := big.NewInt(16)
	Gx := big.NewInt(1)
	Gy := big.NewInt(4)

	edCurve := NewEdwardsCurve(a, d, p, n, Gx, Gy)
	curve := NewECCurve(edCurve)
	runAggregationTest(t, curve)
}

func runAggregationTest(t *testing.T, curve *ECCurve) {
	message := big.NewInt(1337)

	// Participant 1
	priv1, pub1, _ := curve.GenerateKeyPair()
	k1, R1, _ := curve.GenerateNonce()

	// Participant 2
	priv2, pub2, _ := curve.GenerateKeyPair()
	k2, R2, _ := curve.GenerateNonce()

	// Aggregation Stage
	aggPub := curve.AggregatePoints([]ECPoint{pub1, pub2})
	aggR := curve.AggregatePoints([]ECPoint{R1, R2})

	// Partial Signing Stage
	s1, _ := curve.PartialSign(message, priv1, k1, aggR, aggPub)
	s2, _ := curve.PartialSign(message, priv2, k2, aggR, aggPub)

	// Final Aggregation
	combinedSig := curve.AggregateSignatures(aggR, []*big.Int{s1, s2})

	// Verification
	if !curve.Verify(combinedSig, message, aggPub) {
		t.Errorf("Aggregated signature verification failed for curve: %v", curve.curve.Params().Name)
	}
}
