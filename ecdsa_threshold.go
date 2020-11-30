package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"unsafe"
)

func generate_key() *ecdsa.PrivateKey {
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return private
}

func main() {
	m := flag.Int("m", 2, "m in a m/n threshold signature")
	n := flag.Int("n", 3, "n in a m/n threshold signature")
	flag.Parse()
	fmt.Println("Threshold signature setting:")
	fmt.Println("m:", *m)
	fmt.Println("n:", *n)
	fmt.Println()

	var allKeyPairs []*ecdsa.PrivateKey

	for i := 0; i < *n; i++ {
		key := generate_key()
		allKeyPairs = append(allKeyPairs, key)
		fmt.Printf("key pair #%d :\n", i+1)
		fmt.Println("Public key", key.Public())
		fmt.Println("Private key", key)
		fmt.Println("------------------------------\n")
	}

	msg := []byte("hello world")

	// Simulate m/n threshold signature with Bitcoin multisig protocol
	fmt.Println("Test for key [0, 1]")
	for _, i := range []int{0, 1} {
		private := allKeyPairs[i]
		r, s, err := ecdsa.Sign(rand.Reader, private, msg)
		if err == nil {
			fmt.Printf("Key #%d, Message: \"%s\", signature: r:%x, s:%x\n", i+1, msg, r, s)
		} else {
			fmt.Errorf("%s: error signing: %s", msg, err)
		}

		if ecdsa.Verify(&private.PublicKey, msg, r, s) {
			fmt.Printf(
				"Verified for public key[%d] size = %d\n",
				i+1,
				unsafe.Sizeof(*r)+unsafe.Sizeof(*s),
			)
		} else {
			fmt.Errorf("%s: Verify failed", msg)
		}
		fmt.Println()
	}

	fmt.Println("Test for key [0, 2]")
	for _, i := range []int{0, 2} {
		private := allKeyPairs[i]
		r, s, err := ecdsa.Sign(rand.Reader, private, msg)
		if err == nil {
			fmt.Printf("Key #%d, Message: \"%s\", signature: r:%x, s:%x\n", i+1, msg, r, s)
		} else {
			fmt.Errorf("%s: error signing: %s", msg, err)
		}

		if ecdsa.Verify(&private.PublicKey, msg, r, s) {
			fmt.Printf(
				"Verified for public key[%d] size = %d\n",
				i+1,
				unsafe.Sizeof(*r)+unsafe.Sizeof(*s),
			)
		} else {
			fmt.Errorf("%s: Verify failed", msg)
		}
		fmt.Println()
	}

	fmt.Println("Test for key [1, 2]")
	for _, i := range []int{1, 2} {
		private := allKeyPairs[i]
		r, s, err := ecdsa.Sign(rand.Reader, private, msg)
		if err == nil {
			fmt.Printf("Key #%d, Message: \"%s\", signature: r:%x, s:%x\n", i+1, msg, r, s)
		} else {
			fmt.Errorf("%s: error signing: %s", msg, err)
		}

		if ecdsa.Verify(&private.PublicKey, msg, r, s) {
			fmt.Printf(
				"Verified for public key[%d] size = %d\n",
				i+1,
				unsafe.Sizeof(*r)+unsafe.Sizeof(*s),
			)
		} else {
			fmt.Errorf("%s: Verify failed", msg)
		}
		fmt.Println()
	}
}
