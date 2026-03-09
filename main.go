package main

import (
	"crypto/elliptic"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
)

func main() {
	keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
	signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)

	// Keygen flags
	kgCurve := keygenCmd.String("curve", "p256", "Curve type: p256 or edwards")

	// Sign flags
	sCurve := signCmd.String("curve", "p256", "Curve type: p256 or edwards")
	sPriv := signCmd.String("priv", "", "Private key (big int string)")
	sMsg := signCmd.String("msg", "", "Message to sign (string)")

	// Verify flags
	vCurve := verifyCmd.String("curve", "p256", "Curve type: p256 or edwards")
	vPub := verifyCmd.String("pub", "", "Public key (JSON formatted ECPoint)")
	vMsg := verifyCmd.String("msg", "", "Message verified (string)")
	vSig := verifyCmd.String("sig", "", "Signature (JSON formatted SchnorrSignature)")

	if len(os.Args) < 2 {
		fmt.Println("Expected 'keygen', 'sign' or 'verify' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		keygenCmd.Parse(os.Args[2:])
		runKeygen(*kgCurve)
	case "sign":
		signCmd.Parse(os.Args[2:])
		runSign(*sCurve, *sPriv, *sMsg)
	case "verify":
		verifyCmd.Parse(os.Args[2:])
		runVerify(*vCurve, *vPub, *vMsg, *vSig)
	default:
		fmt.Println("Expected 'keygen', 'sign' or 'verify' subcommands")
		os.Exit(1)
	}
}

func getCurve(name string) *ECCurve {
	if name == "edwards" {
		// Sample Twisted Edwards curve
		a := big.NewInt(-1)
		d := big.NewInt(3)
		p := big.NewInt(17)
		n := big.NewInt(16)
		Gx := big.NewInt(1)
		Gy := big.NewInt(4)
		return NewECCurve(NewEdwardsCurve(a, d, p, n, Gx, Gy))
	}
	return NewECCurve(elliptic.P256())
}

func runKeygen(curveName string) {
	curve := getCurve(curveName)
	priv, pub, err := curve.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	output := map[string]interface{}{
		"private": priv.String(),
		"public":  pub,
	}
	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
}

func runSign(curveName, privStr, msgStr string) {
	if privStr == "" || msgStr == "" {
		fmt.Println("Private key and message are required")
		return
	}
	curve := getCurve(curveName)
	priv := new(big.Int)
	priv.SetString(privStr, 10)
	msg := new(big.Int).SetBytes([]byte(msgStr))

	sig, err := curve.Sign(msg, priv)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	data, _ := json.MarshalIndent(sig, "", "  ")
	fmt.Println(string(data))
}

func runVerify(curveName, pubStr, msgStr, sigStr string) {
	if pubStr == "" || msgStr == "" || sigStr == "" {
		fmt.Println("Public key, message, and signature are required")
		return
	}
	curve := getCurve(curveName)
	var pub ECPoint
	if err := json.Unmarshal([]byte(pubStr), &pub); err != nil {
		fmt.Printf("Invalid public key JSON: %v\n", err)
		return
	}
	var sig SchnorrSignature
	if err := json.Unmarshal([]byte(sigStr), &sig); err != nil {
		fmt.Printf("Invalid signature JSON: %v\n", err)
		return
	}
	msg := new(big.Int).SetBytes([]byte(msgStr))

	valid := curve.Verify(&sig, msg, pub)
	fmt.Printf("{\"valid\": %v}\n", valid)
}
