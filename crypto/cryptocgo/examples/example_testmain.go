package main

import "github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo"

var data = []byte("test")

func main() {
	vcrypto := cryptocgo.NewVirgilCrypto()
	kp1, err := vcrypto.GenerateKeypair()
	check(err)

	sign, err := vcrypto.Sign(data, kp1.PrivateKey())
	check(err)

	err = vcrypto.VerifySignature(data, sign, kp1.PublicKey())
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
