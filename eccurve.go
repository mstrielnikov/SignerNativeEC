package main

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
)

// ECPoint represents a point on an elliptic curve.
type ECPoint struct {
	X, Y *big.Int
}

// ECPointGen creates a new ECPoint from given coordinates.
func ECPointGen(x, y *big.Int) ECPoint {
	return ECPoint{X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
}

// IsEqual checks if two elliptic curve points are equal.
func (ecp ECPoint) IsEqual(ecPoint ECPoint) bool {
	return ecp.X.Cmp(ecPoint.X) == 0 && ecp.Y.Cmp(ecPoint.Y) == 0
}

// Signer is an interface for signing messages.
type Signer interface {
	Sign(message *big.Int, priv *big.Int) (*SchnorrSignature, error)
}

// Verifier is an interface for verifying signatures.
type Verifier interface {
	Verify(sig *SchnorrSignature, message *big.Int, pub ECPoint) bool
}

// ECCurve implements methods for elliptic curve operations.
type ECCurve struct {
	curve elliptic.Curve
}

// NewECCurve initializes a new ECCurve.
func NewECCurve(curve elliptic.Curve) *ECCurve {
	return &ECCurve{curve: curve}
}

// BasePointGGet returns the base point (generator) of the curve.
func (ec *ECCurve) BasePointGGet() ECPoint {
	x, y := ec.curve.Params().Gx, ec.curve.Params().Gy
	return ECPoint{X: x, Y: y}
}

// ScalarMult multiplies a point by a scalar and returns the result.
func (ec *ECCurve) ScalarMult(scalar *big.Int, point ECPoint) ECPoint {
	x, y := ec.curve.ScalarMult(point.X, point.Y, scalar.Bytes())
	return ECPoint{X: x, Y: y}
}

// IsOnCurveCheck checks if a given point is on the curve.
func (ec *ECCurve) IsOnCurveCheck(point ECPoint) bool {
	return ec.curve.IsOnCurve(point.X, point.Y)
}

// AddECPoints adds two elliptic curve points and returns the result.
func (ec *ECCurve) AddECPoints(pointA, pointB ECPoint) ECPoint {
	x, y := ec.curve.Add(pointA.X, pointA.Y, pointB.X, pointB.Y)
	return ECPoint{X: x, Y: y}
}

// DoubleECPoints doubles the given elliptic curve point and returns the result.
func (ec *ECCurve) DoubleECPoints(point ECPoint) ECPoint {
	x, y := ec.curve.Double(point.X, point.Y)
	return ECPoint{X: x, Y: y}
}

// AggregatePoints sums multiple elliptic curve points.
func (ec *ECCurve) AggregatePoints(points []ECPoint) ECPoint {
	if len(points) == 0 {
		return ECPoint{}
	}
	resX, resY := points[0].X, points[0].Y
	for i := 1; i < len(points); i++ {
		resX, resY = ec.curve.Add(resX, resY, points[i].X, points[i].Y)
	}
	return ECPoint{X: resX, Y: resY}
}

// Negate returns the additive inverse of a point.
func (ec *ECCurve) Negate(point ECPoint) ECPoint {
	if _, ok := ec.curve.(*EdwardsCurve); ok {
		// Edwards inverse of (x, y) is (-x, y)
		nx := new(big.Int).Sub(ec.curve.Params().P, point.X)
		nx.Mod(nx, ec.curve.Params().P)
		return ECPoint{X: nx, Y: point.Y}
	}
	// Weierstrass inverse of (x, y) is (x, -y)
	ny := new(big.Int).Sub(ec.curve.Params().P, point.Y)
	ny.Mod(ny, ec.curve.Params().P)
	return ECPoint{X: point.X, Y: ny}
}

// ECPointToString serializes an ECPoint to a JSON-encoded string.
func ECPointToString(point ECPoint) string {
	data, _ := json.Marshal(point)
	return string(data)
}

// StringToECPoint deserializes an ECPoint from a JSON-encoded string.
func StringToECPoint(s string) ECPoint {
	var point ECPoint
	_ = json.Unmarshal([]byte(s), &point)
	return point
}

// PrintECPoint prints the coordinates of an ECPoint.
func PrintECPoint(point ECPoint) {
	if point.X == nil || point.Y == nil {
		fmt.Println("Infinity/Nil Point")
		return
	}
	fmt.Printf("X: %s\nY: %s\n", point.X.String(), point.Y.String())
}
