# NativeSignersECC

[![Go Reference](https://pkg.go.dev/badge/github.com/mstrielnikov/ECCSignWrapper.svg)](https://pkg.go.dev/github.com/mstrielnikov/ECCSignWrapper)
[![Go Report Card](https://goreportcard.com/badge/github.com/mstrielnikov/ECCSignWrapper)](https://goreportcard.com/report/github.com/mstrielnikov/ECCSignWrapper)

A lightweight Go wrapper library designed to simplify elliptic curve cryptography (ECC) operations and provide a native implementation of **Schnorr Signatures**. It abstracts the complexities of the `crypto/elliptic` package into a more ergonomic and developer-friendly API.

## 🚀 Key Features

- **Simplified ECC Algebra**: Clean methods for scalar multiplication, point addition, and point doubling.
- **Generic Signer Interface**: Abstract `Signer` and `Verifier` interfaces for flexible implementation.
- **Twisted Edwards Support**: Native implementation of Twisted Edwards curves, compatible with the common signing logic.
- **Native Schnorr Signatures**: High-level API for generating and verifying Schnorr signatures across different curve types.
- **Safe and Verified**: Comprehensive test suite ensuring mathematical correctness for both Weierstrass and Edwards curves.

## 📦 Core Concepts

### `Signer` & `Verifier`

Generic interfaces for signing operations, allowing for different curve parameterizations.

```go
type Signer interface {
    Sign(message *big.Int, priv *big.Int) (*SchnorrSignature, error)
}

type Verifier interface {
    Verify(sig *SchnorrSignature, message *big.Int, pub ECPoint) bool
}
```

### `ECPoint`

Represents a point $(x, y)$ on any supported elliptic curve.

```go
type ECPoint struct {
    X, Y *big.Int
}
```

### `SchnorrSignature`

Structure representing the $(R, s)$ components of a Schnorr signature.

## 🛠 Installation

```bash
go get github.com/mstrielnikov/ECCSignWrapper
```

## 📖 Getting Started

### Initializing a Curve (Weierstrass)

```go
import "crypto/elliptic"

curve := NewECCurve(elliptic.P256())
```

### Initializing a Curve (Edwards)

```go
// Example parameters for a Twisted Edwards curve
edCurve := NewEdwardsCurve(a, d, p, n, Gx, Gy)
curve := NewECCurve(edCurve)
```

### Key Generation and Signing

```go
// Generate keys (returns *big.Int private and ECPoint public)
priv, pub, _ := curve.GenerateKeyPair()

// Message to sign
message := new(big.Int).SetBytes([]byte("Hello, ECC!"))

// Sign the message
signature, _ := curve.Sign(message, priv)
```

### Verifying a Signature

```go
isValid := curve.Verify(signature, message, pub)
if isValid {
    fmt.Println("Signature is valid!")
}
```

## 💻 CLI Interface

The library provides a built-in CLI for common cryptographic operations.

### Key Generation

```bash
go run . keygen --curve p256
# or
go run . keygen --curve edwards
```

### Signing a Message

```bash
go run . sign --curve p256 --priv "YOUR_PRIVATE_KEY" --msg "Hello World"
```

### Verifying a Signature

```bash
go run . verify --curve p256 --pub '{"X":..., "Y":...}' --msg "Hello World" --sig '{"R":..., "S":...}'
```

## 🧪 Testing

The library includes a robust test suite covering ECC algebra correctness and signature verification edge cases.

```bash
go test -v ./...
```

### Demo Results

<p align="center">
  <img title="Algebra Tests" src="./pics/demo_tests_wrapper.png" width="45%"/>
  <img title="Schnorr Tests" src="./pics/demo_tests_schnorr_sign.png" width="45%"/>
</p>

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details (if applicable).
