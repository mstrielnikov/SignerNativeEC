package main

import (
	"crypto/elliptic"
	"math/big"
)

// EdwardsCurve implements the elliptic.Curve interface for Twisted Edwards curves.
// Equation: ax^2 + y^2 = 1 + dx^2y^2
type EdwardsCurve struct {
	*elliptic.CurveParams
	A *big.Int // The 'a' parameter in ax^2 + y^2 = 1 + dx^2y^2
	D *big.Int // The 'd' parameter in ax^2 + y^2 = 1 + dx^2y^2
}

// NewEdwardsCurve creates a new Twisted Edwards curve.
func NewEdwardsCurve(a, d, p, n, Gx, Gy *big.Int) *EdwardsCurve {
	return &EdwardsCurve{
		CurveParams: &elliptic.CurveParams{
			P:       p,
			N:       n,
			Gx:      Gx,
			Gy:      Gy,
			BitSize: p.BitLen(),
			Name:    "TwistedEdwards",
		},
		A: a,
		D: d,
	}
}

// IsOnCurve checks if the given (x,y) point is on the curve.
func (ec *EdwardsCurve) IsOnCurve(x, y *big.Int) bool {
	// ax^2 + y^2 = 1 + dx^2y^2
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, ec.P)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, ec.P)

	lhs := new(big.Int).Mul(ec.A, x2)
	lhs.Add(lhs, y2)
	lhs.Mod(lhs, ec.P)

	rhs := new(big.Int).Mul(ec.D, x2)
	rhs.Mul(rhs, y2)
	rhs.Add(rhs, big.NewInt(1))
	rhs.Mod(rhs, ec.P)

	return lhs.Cmp(rhs) == 0
}

// Add adds two points on the Twisted Edwards curve.
func (ec *EdwardsCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// Standard Twisted Edwards addition law
	// x3 = (x1y2 + y1x2) / (1 + dx1x2y1y2)
	// y3 = (y1y2 - ax1x2) / (1 - dx1x2y1y2)

	x1y2 := new(big.Int).Mul(x1, y2)
	y1x2 := new(big.Int).Mul(y1, x2)
	numX := new(big.Int).Add(x1y2, y1x2)
	numX.Mod(numX, ec.P)

	ax1x2 := new(big.Int).Mul(ec.A, x1)
	ax1x2.Mul(ax1x2, x2)
	y1y2 := new(big.Int).Mul(y1, y2)
	numY := new(big.Int).Sub(y1y2, ax1x2)
	numY.Mod(numY, ec.P)

	dx1x2y1y2 := new(big.Int).Mul(ec.D, x1)
	dx1x2y1y2.Mul(dx1x2y1y2, x2)
	dx1x2y1y2.Mul(dx1x2y1y2, y1)
	dx1x2y1y2.Mul(dx1x2y1y2, y2)
	dx1x2y1y2.Mod(dx1x2y1y2, ec.P)

	denX := new(big.Int).Add(big.NewInt(1), dx1x2y1y2)
	denX.Mod(denX, ec.P)
	denY := new(big.Int).Sub(big.NewInt(1), dx1x2y1y2)
	denY.Mod(denY, ec.P)

	invX := new(big.Int).ModInverse(denX, ec.P)
	invY := new(big.Int).ModInverse(denY, ec.P)

	if invX == nil || invY == nil {
		return nil, nil // Error in addition (should not happen for prime P and valid points)
	}

	resX := new(big.Int).Mul(numX, invX)
	resX.Mod(resX, ec.P)
	resY := new(big.Int).Mul(numY, invY)
	resY.Mod(resY, ec.P)

	return resX, resY
}

// Double doubles a point on the Twisted Edwards curve.
func (ec *EdwardsCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return ec.Add(x1, y1, x1, y1)
}

// ScalarMult multiplies a point by a scalar k.
func (ec *EdwardsCurve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	// Standard double-and-add algorithm
	// Identity for Edwards is (0, 1)
	resX, resY := big.NewInt(0), big.NewInt(1)
	baseX, baseY := new(big.Int).Set(x1), new(big.Int).Set(y1)

	scalar := new(big.Int).SetBytes(k)
	for i := scalar.BitLen() - 1; i >= 0; i-- {
		resX, resY = ec.Double(resX, resY)
		if scalar.Bit(i) == 1 {
			resX, resY = ec.Add(resX, resY, baseX, baseY)
		}
	}
	return resX, resY
}

// ScalarBaseMult multiplies the generator point G by a scalar k.
func (ec *EdwardsCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return ec.ScalarMult(ec.Gx, ec.Gy, k)
}
