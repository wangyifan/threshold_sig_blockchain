package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/pairing"
	"go.dedis.ch/kyber/pairing/bn256"
	"go.dedis.ch/kyber/share"
	"go.dedis.ch/kyber/sign/bls"
)

type SigShare []byte

// Index returns the index i of the TBLS share Si.
func (s SigShare) Index() (int, error) {
	var index uint16
	buf := bytes.NewReader(s)
	err := binary.Read(buf, binary.BigEndian, &index)
	if err != nil {
		return -1, err
	}
	return int(index), nil
}

// Value returns the value v of the TBLS share Si.
func (s *SigShare) Value() []byte {
	return []byte(*s)[2:]
}

func recoverSig(suite pairing.Suite, public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error) {
	sigShares := make([]*share.PubShare, 0)
	for _, sig := range sigs {
		s := SigShare(sig)
		i, err := s.Index()
		if err = bls.Verify(suite, public.Eval(i).V, msg, s.Value()); err != nil {
			return nil, err
		}
		v := suite.G1().Point()
		v.UnmarshalBinary(s.Value())
		sigShares = append(sigShares, &share.PubShare{I: i, V: v})
	}
	commit, _ := share.RecoverCommit(suite.G1(), sigShares, t, n)
	sig, _ := commit.MarshalBinary()
	return sig, nil
}

func main() {
	msg := []byte("Hello Threshold Signature")
	suite := bn256.NewSuite()
	// This is a 3/3 threshold BLS
	n := 3
	t := 3
	fmt.Printf("n = %v, t = %v\n\n", n, t)
	// we need n secrets
	secrets := make([]kyber.Scalar, n)
	for i := 0; i < n; i++ {
		// randomness for secret, we just need a scalar here, so it
		// does not matter using g1 or g2
		secrets[i] = suite.G1().Scalar().Pick(suite.RandomStream())
	}

	priPolyList := make([]*share.PriPoly, n)
	pubPolyList := make([]*share.PubPoly, n)
	priShares := make([][]*share.PriShare, n)
	pubShares := make([][]*share.PubShare, n)

	// create 3 pri and pub polys from its secret
	// and store all its shares
	for index, secret := range secrets {
		priPoly := share.NewPriPoly(
			suite.G2(),
			t,
			secret,
			suite.RandomStream(),
		)

		pubPoly := priPoly.Commit(
			suite.G2().Point().Base(),
		)
		priPolyList[index] = priPoly
		pubPolyList[index] = pubPoly
		priShares[index] = priPoly.Shares(n)
		pubShares[index] = pubPoly.Shares(n)

		coeff := priPoly.Coefficients()
		fmt.Printf("Polynomial #%d\n", index+1)
		for i := 0; i < t; i++ {
			fmt.Printf("a%d: %v\n", i, coeff[i])
		}
		fmt.Println()
	}

	for i := 0; i < n; i++ {
		fmt.Printf("Private Share #%d\n", i+1)
		for j, share := range priShares[i] {
			fmt.Printf("Private[%d, %d]: %v\n", i+1, j+1, share.V)
		}
	}
	fmt.Println()

	for i := 0; i < n; i++ {
		fmt.Printf("Public Share #%d\n", i+1)
		for j, share := range pubShares[i] {
			fmt.Printf("Public[%d, %d]: %v\n", i+1, j+1, share.V)
		}
	}
	fmt.Println()

	// aggregated private key
	dkgShares := make([]*share.PriShare, n)
	for i := 0; i < n; i++ {
		acc := suite.G2().Scalar().Zero()
		for j := 0; j < n; j++ {
			acc = suite.G2().Scalar().Add(acc, priShares[j][i].V)
		}
		dkgShares[i] = &share.PriShare{i, acc}
		fmt.Printf("Local Private Key #%d: %v\n", dkgShares[i].I, dkgShares[i].V)
	}
	fmt.Println()

	// sig the message locally
	sigShares := make([][]byte, n)
	for i, x := range dkgShares {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint16(x.I))
		s, _ := bls.Sign(suite, x.V, msg)
		binary.Write(buf, binary.BigEndian, s)
		sigShares[i] = buf.Bytes()
		fmt.Printf("Signature share #%d: %x\n", i+1, s)
	}
	fmt.Println()

	pubPolyAll := pubPolyList[0]
	for i := 1; i < n; i++ {
		pubPolyAll, _ = pubPolyAll.Add(pubPolyList[i])
	}

	allSig, err := recoverSig(suite, pubPolyAll, msg, sigShares, t, n)
	fmt.Printf("Group signature #1: %x\n", allSig)
	err = bls.Verify(suite, pubPolyAll.Commit(), msg, allSig)
	if err != nil {
		fmt.Printf("Group signature verified failed, %v\n", err)
	} else {
		fmt.Printf("Group signature verified true\n")
	}

	// sign with aggregated private key
	allPriKey, _ := share.RecoverSecret(suite.G2(), dkgShares, t, n)
	s, _ := bls.Sign(suite, allPriKey, msg)
	fmt.Printf("Group signature #2: %x\n", s)

	fmt.Println("\n\n========================================================\n\n")
}
