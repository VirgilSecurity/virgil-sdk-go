package main

import "github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo"

var data = []byte("test")

func main() {
	vcrypto := cryptocgo.NewVirgilCrypto()
	key, err := vcrypto.GenerateKeypair()
	check(err)

	sign, err := vcrypto.Sign(data, key)
	check(err)

	err = vcrypto.VerifySignature(data, sign, key.PublicKey())
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
