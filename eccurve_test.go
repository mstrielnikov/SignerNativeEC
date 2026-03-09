package main

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestECCAlgebraEquation(t *testing.T) {
	curveParam := elliptic.P256()
	Curve := NewECCurve(curveParam)

	G := Curve.BasePointGGet()
	k := SetRandom(256)
	d := SetRandom(256)

	H1 := Curve.ScalarMult(d, G)
	H2 := Curve.ScalarMult(k, H1)

	H3 := Curve.ScalarMult(k, G)
	H4 := Curve.ScalarMult(d, H3)

	result := H2.IsEqual(&H4)

	if !Curve.IsOnCurveCheck(H2) {
		t.Fatal("H2 is not on the curve")
	}

	if !Curve.IsOnCurveCheck(H4) {
		t.Fatal("H4 is not on the curve")
	}

	if !result {
		t.Fatal("ECC Algebra Equation test failed")
	}
}

func TestAdditionDoubling(t *testing.T) {
	curveParam := elliptic.P256()
	Curve := NewECCurve(curveParam)
	G := Curve.BasePointGGet()

	sum := Curve.AddECPoints(G, G)

	double := Curve.DoubleECPoints(G)

	if !Curve.IsOnCurveCheck(sum) {
		t.Fatal("(A + A) point is not on the curve")
	}

	if !Curve.IsOnCurveCheck(double) {
		t.Fatal("(2A) point is not on the curve")
	}

	if !sum.IsEqual(&double) {
		t.Fatal("ECC doubling addition test failed")
	}
}

func TestECPointSerialization(t *testing.T) {
	curveParam := elliptic.P256()
	Curve := NewECCurve(curveParam)

	G := Curve.BasePointGGet()

	serialized := ECPointToString(G)
	deserialized := StringToECPoint(serialized)

	if !G.IsEqual(&deserialized) {
		t.Fatal("ECPoint serialization/deserialization failed")
	}
}

func TestIsOnCurveCheck(t *testing.T) {
	curveParam := elliptic.P256()
	Curve := NewECCurve(curveParam)

	G := Curve.BasePointGGet()

	if !Curve.IsOnCurveCheck(G) {
		t.Fatal("Generator point should be on the curve")
	}

	invalidPoint := ECPoint{X: big.NewInt(1), Y: big.NewInt(1)}
	if Curve.IsOnCurveCheck(invalidPoint) {
		t.Fatal("Point (1,1) should not be on the curve")
	}
}
