package main

import (
	"crypto/ecdsa"
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
func (ec *ECCurve) GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(ec.curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	if !ec.IsOnCurveCheck(ECPoint{priv.X, priv.Y}) {
		return nil, nil, fmt.Errorf("private key point in not on the curve")
	}

	return priv, &priv.PublicKey, nil
}

// Sign generates a Schnorr signature for a given message and private key.
func (ec *ECCurve) Sign(message *big.Int, priv *ecdsa.PrivateKey) (*SchnorrSignature, error) {
	k, err := rand.Int(rand.Reader, ec.curve.Params().N)
	if err != nil {
		return nil, err
	}

	if k.Sign() == 0 {
		return nil, fmt.Errorf("nonce k cannot be zero")
	}

	Rx, _ := ec.curve.ScalarBaseMult(k.Bytes())

	r := hashPoints(Rx, priv.PublicKey.X, priv.PublicKey.Y, message)

	s := new(big.Int).Mul(r, priv.D)
	s.Add(s, k)
	s.Mod(s, ec.curve.Params().N)

	if s.Sign() == 0 {
		return nil, fmt.Errorf("signature s cannot be zero")
	}

	return &SchnorrSignature{R: Rx, S: s}, nil
}

// Verify verifies a Schnorr signature for a given message and public key.
func (ec *ECCurve) Verify(signature *SchnorrSignature, message *big.Int, pub *ecdsa.PublicKey) bool {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	if pub == nil || pub.X == nil || pub.Y == nil {
		return false
	}

	if signature == nil || signature.R == nil || signature.S == nil {
		return false
	}

	e := hashPoints(signature.R, pub.X, pub.Y, message)

	var Rx, Ry *big.Int
	Rx, Ry = ec.curve.ScalarBaseMult(signature.S.Bytes())
	if Ry == nil {
		return false
	}

	tempX, tempY := ec.curve.ScalarMult(pub.X, pub.Y, e.Bytes())
	if tempY == nil {
		return false
	}

	negY := new(big.Int).Neg(tempY)
	negY.Mod(negY, ec.curve.Params().P)
	Rx, Ry = ec.curve.Add(Rx, Ry, tempX, negY)
	if Ry == nil {
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
