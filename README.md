# NativeSignersECC

[![Go Reference](https://pkg.go.dev/badge/github.com/mstrielnikov/ECCSignWrapper.svg)](https://pkg.go.dev/github.com/mstrielnikov/ECCSignWrapper)
[![Go Report Card](https://goreportcard.com/badge/github.com/mstrielnikov/ECCSignWrapper)](https://goreportcard.com/report/github.com/mstrielnikov/ECCSignWrapper)

A lightweight Go wrapper library designed to simplify elliptic curve cryptography (ECC) operations and provide a native implementation of **Schnorr Signatures**. It abstracts the complexities of the `crypto/elliptic` package into a more ergonomic and developer-friendly API.

## 🚀 Key Features

- **Simplified ECC Algebra**: Clean methods for scalar multiplication, point addition, and point doubling.
- **Native Schnorr Signatures**: High-level API for generating and verifying Schnorr signatures.
- **Ergonomic Point Handling**: `ECPoint` struct for easy coordinate management.
- **Serialization Support**: Built-in JSON serialization for elliptic curve points.
- **Safe and Verified**: Comprehensive test suite ensuring mathematical correctness.

## 📦 Core Concepts

### `ECCurve`

The central component that wraps a `crypto/elliptic.Curve`. It provides the high-level algebra methods.

### `ECPoint`

Represents a point $(x, y)$ on the elliptic curve.

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

### Initializing a Curve

```go
import "crypto/elliptic"

curve := NewECCurve(elliptic.P256())
```

### Key Generation and Signing

```go
// Generate keys
priv, pub, _ := curve.GenerateKeyPair()

// Message to sign (as big.Int)
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
