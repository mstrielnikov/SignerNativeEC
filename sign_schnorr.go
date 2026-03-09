package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// SchnorrSignature represents a Schnorr signature.
type SchnorrSignature struct {
	R, S *big.Int
}

// GenerateKeyPair generates a key pair for Schnorr signatures.
func (ec *ECCurve) GenerateKeyPair() (*big.Int, ECPoint, error) {
	priv, err := rand.Int(rand.Reader, ec.curve.Params().N)
	if err != nil {
		return nil, ECPoint{}, err
	}

	pubX, pubY := ec.curve.ScalarBaseMult(priv.Bytes())
	pub := ECPoint{X: pubX, Y: pubY}

	if !ec.IsOnCurveCheck(pub) {
		return nil, ECPoint{}, fmt.Errorf("public key point in not on the curve")
	}

	return priv, pub, nil
}

// Sign generates a Schnorr signature for a given message and private key.
func (ec *ECCurve) Sign(message *big.Int, priv *big.Int) (*SchnorrSignature, error) {
	k, err := rand.Int(rand.Reader, ec.curve.Params().N)
	if err != nil {
		return nil, err
	}

	if k.Sign() == 0 {
		return nil, fmt.Errorf("nonce k cannot be zero")
	}

	Rx, _ := ec.curve.ScalarBaseMult(k.Bytes())

	// Public key pub = g^priv
	pubX, pubY := ec.curve.ScalarBaseMult(priv.Bytes())

	r := hashPoints(Rx, pubX, pubY, message)

	s := new(big.Int).Mul(r, priv)
	s.Add(s, k)
	s.Mod(s, ec.curve.Params().N)

	if s.Sign() == 0 {
		return nil, fmt.Errorf("signature s cannot be zero")
	}

	return &SchnorrSignature{R: Rx, S: s}, nil
}

// GenerateNonce generates a random nonce and its corresponding point.
func (ec *ECCurve) GenerateNonce() (*big.Int, ECPoint, error) {
	k, err := rand.Int(rand.Reader, ec.curve.Params().N)
	if err != nil {
		return nil, ECPoint{}, err
	}
	if k.Sign() == 0 {
		return nil, ECPoint{}, fmt.Errorf("nonce cannot be zero")
	}
	Rx, Ry := ec.curve.ScalarBaseMult(k.Bytes())
	return k, ECPoint{X: Rx, Y: Ry}, nil
}

// PartialSign generates a partial signature for aggregation.
func (ec *ECCurve) PartialSign(message *big.Int, priv *big.Int, k *big.Int, aggR ECPoint, aggPub ECPoint) (*big.Int, error) {
	e := hashPoints(aggR.X, aggPub.X, aggPub.Y, message)

	s := new(big.Int).Mul(e, priv)
	s.Add(s, k)
	s.Mod(s, ec.curve.Params().N)

	return s, nil
}

// AggregateSignatures combines partial signatures into a single Schnorr signature.
func (ec *ECCurve) AggregateSignatures(aggR ECPoint, partialS []*big.Int) *SchnorrSignature {
	s := new(big.Int)
	for _, ps := range partialS {
		s.Add(s, ps)
	}
	s.Mod(s, ec.curve.Params().N)
	return &SchnorrSignature{R: aggR.X, S: s}
}

// Verify verifies a Schnorr signature for a given message and public key.
func (ec *ECCurve) Verify(signature *SchnorrSignature, message *big.Int, pub ECPoint) bool {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	if pub.X == nil || pub.Y == nil {
		return false
	}

	if signature == nil || signature.R == nil || signature.S == nil {
		return false
	}

	e := hashPoints(signature.R, pub.X, pub.Y, message)

	// gs = g^s
	gsX, gsY := ec.curve.ScalarBaseMult(signature.S.Bytes())
	if gsY == nil {
		return false
	}

	// ep = pub^e
	epX, epY := ec.curve.ScalarMult(pub.X, pub.Y, e.Bytes())
	if epY == nil {
		return false
	}

	// target = gs - ep
	negEP := ec.Negate(ECPoint{X: epX, Y: epY})
	Rx, _ := ec.curve.Add(gsX, gsY, negEP.X, negEP.Y)
	if Rx == nil {
		return false
	}

	return signature.R.Cmp(Rx) == 0
}

// hashPoints concatenates the coordinates of given points and the message, and then hashes the result using SHA-256.
func hashPoints(points ...*big.Int) *big.Int {
	hash := sha256.New()
	for _, point := range points {
		if point != nil {
			hash.Write(point.Bytes())
		}
	}
	return new(big.Int).SetBytes(hash.Sum(nil))
}
