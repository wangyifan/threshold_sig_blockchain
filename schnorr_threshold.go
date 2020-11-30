// tokucore
//
// Copyright 2019 by KeyFuse Labs
// BSD License

// tokucore
//
// Copyright 2019 by KeyFuse Labs
// BSD License

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
	"unsafe"

	"github.com/keyfuse/tokucore/xcrypto/schnorr"
	"github.com/keyfuse/tokucore/xcrypto/secp256k1"
)

type PrvKey ecdsa.PrivateKey

type PubKey ecdsa.PublicKey

type SchnorrParty struct {
	k0    *big.Int
	N     *big.Int
	prv   *PrvKey
	pub   *PubKey
	hash  []byte
	curve elliptic.Curve
	r     *secp256k1.Scalar
	sig   []byte
}

func calcHash(buf []byte, hasher hash.Hash) []byte {
	if _, err := hasher.Write(buf); err != nil {
		panic(err)
	}
	return hasher.Sum(nil)
}

func Sha256(data []byte) []byte {
	return calcHash(data, sha256.New())
}

func DoubleSha256(data []byte) []byte {
	hash := calcHash(data, sha256.New())
	return calcHash(hash, sha256.New())
}

func PrvKeyFromBytes(key []byte) *PrvKey {
	curve := secp256k1.SECP256K1()
	x, y := curve.ScalarBaseMult(key)
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(key),
	}
	return (*PrvKey)(priv)
}

func (p *PrvKey) PubKey() *PubKey {
	return (*PubKey)(&p.PublicKey)
}

func (p *PubKey) Add(p2 *PubKey) *PubKey {
	x1 := p.X
	y1 := p.Y
	curve := p.Curve

	x2 := p2.X
	y2 := p2.Y
	x3, y3 := curve.Add(x1, y1, x2, y2)
	return &PubKey{
		X:     x3,
		Y:     y3,
		Curve: curve,
	}
}

func NewSchnorrParty(prv *PrvKey) *SchnorrParty {
	pub := prv.PubKey()
	curve := pub.Curve
	N := curve.Params().N
	return &SchnorrParty{
		N:     N,
		prv:   prv,
		pub:   pub,
		curve: curve,
	}
}

func MakePrivateKey(hexint string) *PrvKey {
	bigint, _ := new(big.Int).SetString(hexint, 16)
	return PrvKeyFromBytes(bigint.Bytes())
}

func generateSignature(party *SchnorrParty, shareR *secp256k1.Scalar, sharePub *PubKey) []byte {
	k0 := party.k0
	m := party.hash
	N := party.N
	prv := party.prv
	curve := party.curve

	// e = int(hash(bytes(x(R)) || bytes(dG) || m)) mod n
	e := schnorr.GetE(curve, m, sharePub.X, sharePub.Y, schnorr.IntToByte(shareR.X))

	// ed
	ed := new(big.Int)
	ed.Mul(e, prv.D)

	// s = k + ed, ed is hash(P, R, m) * private
	k := schnorr.GetK(curve, shareR.Y, k0)
	s := new(big.Int)
	s.Add(k, ed)
	s.Mod(s, N)

	party.sig = schnorr.IntToByte(s)
	fmt.Printf("party sig: %x\n", party.sig)
	return party.sig
}

func pickParties(picks []bool, allParties []*SchnorrParty) []*SchnorrParty {
	parties := make([]*SchnorrParty, 0)
	for i := 0; i < len(picks); i++ {
		if picks[i] {
			parties = append(parties, allParties[i])
		}
	}

	return parties
}

func getScalar(party *SchnorrParty, hash []byte) *secp256k1.Scalar {
	prv := party.prv
	pub := prv.PubKey()
	curve := pub.Curve
	d := schnorr.IntToByte(prv.D)

	// Scalar R.
	// k' = int(hash(bytes(d) || m)) mod n
	k0, err := schnorr.GetK0(hash, d, party.N)
	if err != nil {
		panic("k0 panic")
	}
	party.k0 = k0
	party.hash = hash

	rx, ry := curve.ScalarBaseMult(k0.Bytes())
	party.r = secp256k1.NewScalar(rx, ry)
	return party.r
}

func main() {
	allParties := []*SchnorrParty{
		NewSchnorrParty(MakePrivateKey("15bafcb56279dbfd985d4d17cdaf9bbfc6701b628f9fb00d6d1e0d2cb503ede3")), // 1
		NewSchnorrParty(MakePrivateKey("76818c328b8aa1e8f17bd599016fef8134b7d5ec315e0b6373953da7e8b5c0c9")), // 2
		NewSchnorrParty(MakePrivateKey("02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6")), // 3
		NewSchnorrParty(MakePrivateKey("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817")), // 4
		NewSchnorrParty(MakePrivateKey("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F8")), // 5
		NewSchnorrParty(MakePrivateKey("026D7F1D87AB3BBC8BC01F95D9AECE1E659D6E33C880F8EFA65FACF83E698BBB")), // 6
		NewSchnorrParty(MakePrivateKey("03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A")), // 7
		NewSchnorrParty(MakePrivateKey("031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD07")), // 8
		NewSchnorrParty(MakePrivateKey("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F8")), // 9
		NewSchnorrParty(MakePrivateKey("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817")), // 10
	}

	// choose different schnorr party combination for n/m threshold signature
	//picks := []bool{true, false, false, true, true, true, true, true, true, true}
	picks := []bool{false, false, false, true, true, true, true, true, true, false}
	pickedParties := pickParties(picks, allParties)

	// phase 0
	curve := pickedParties[0].curve
	hash := DoubleSha256([]byte{0x01, 0x02, 0x03, 0x04})

	// phase 1, aggregate pub key
	sharePub := pickedParties[0].pub
	for i := 1; i < len(pickedParties); i++ {
		sharePub = sharePub.Add(pickedParties[i].pub)
	}

	fmt.Printf("Single share pub size: %d \n", unsafe.Sizeof(*(sharePub.Y))+unsafe.Sizeof(*(sharePub.X))+unsafe.Sizeof(sharePub.Curve))

	// phase 2, get scalar R
	allScalarR := make([]*secp256k1.Scalar, 0)
	for i := 0; i < len(pickedParties); i++ {
		allScalarR = append(allScalarR, getScalar(pickedParties[i], hash))
	}

	// phase 3, get shared scalar R
	shareScalarR := secp256k1.NewScalar(allScalarR[0].X, allScalarR[0].Y)
	for i := 1; i < len(allScalarR); i++ {
		shareScalarR = shareScalarR.Add(curve, allScalarR[i])
	}

	// phase 4. sign the hash
	for i := 0; i < len(pickedParties); i++ {
		generateSignature(pickedParties[i], shareScalarR, sharePub)
	}

	// phase 5, aggregate signature
	aggs := new(big.Int)
	sigFinal := make([]byte, 64)

	for _, party := range pickedParties {
		s := new(big.Int).SetBytes(party.sig[:])
		aggs.Add(aggs, s)
		aggs = aggs.Mod(aggs, party.N)
	}

	copy(sigFinal[:32], schnorr.IntToByte(shareScalarR.X))
	copy(sigFinal[32:], schnorr.IntToByte(aggs))

	// phase 6, verify the signature
	r := new(big.Int)
	r.SetBytes(sigFinal[:32])
	s := new(big.Int)
	s.SetBytes(sigFinal[32:])

	fmt.Println("-------------------------------------------------")
	pass := schnorr.Verify((*ecdsa.PublicKey)(sharePub), hash, r, s)
	fmt.Printf("Aggregated scalar: %v\n", shareScalarR)
	fmt.Printf("final pub key: %x\n", (*ecdsa.PublicKey)(sharePub))
	fmt.Printf("final sig: r %x, s %x\n", r, s)
	fmt.Printf("final verify: %t\n", pass)
}
