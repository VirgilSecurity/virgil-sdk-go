// +build integration

package sdk_test

import (
	"fmt"
	"log"
	"os"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/sdk"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/session"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/storage"
)

func ExampleCardManager_PublishCard() {
	const identity = "Alice1"
	var crypto crypto.Crypto

	// generate a key pair
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyStorage := storage.NewVirgilPrivateKeyStorage(&storage.FileStorage{})

	// clean up storage before write
	privateKeyStorage.Delete(identity)

	// save a private key into key storage
	err = privateKeyStorage.Store(keypair, identity, nil)
	if err != nil {
		log.Fatal(err)
	}

	cardManager := setupCardManager()
	// publish user's on the Cards Service
	card, err := cardManager.PublishCard(&sdk.CardParams{
		PrivateKey: keypair,
		Identity:   identity,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(card.Identity)
	// Output: Alice1
}

func Example_encryptDecrypt() {
	const (
		Alice1 = "Alice1"
		Bob1   = "Bob1"
	)
	text := fmt.Sprintf("Hello, %s!", Bob1)

	registerCard(Alice1)
	registerCard(Bob1)
	encryptedMsg := encrypt(Alice1, Bob1, []byte(text))
	decryptedMsg := decrypt(Alice1, Bob1, encryptedMsg)

	fmt.Printf("%s\n", decryptedMsg)
	// Output: Hello, Bob1!
}

func encrypt(from string, to string, messageToEncrypt []byte) []byte {
	var crypto crypto.Crypto

	privateKeyStorage := storage.NewVirgilPrivateKeyStorage(&storage.FileStorage{})

	// prepare a user's private key from a device storage
	fromPrivateKey, _, err := privateKeyStorage.Load(from)
	if err != nil {
		log.Fatal(err)
	}

	cardManager := setupCardManager()

	// using cardManager search for Bob1's cards on Cards Service
	cards, err := cardManager.SearchCards(to)
	if err != nil {
		log.Fatal(err)
	}

	// sign a message with a private key then encrypt using Bob1's public keys
	encryptedMessage, err := crypto.SignThenEncrypt(messageToEncrypt, fromPrivateKey, cards.ExtractPublicKeys()...)
	if err != nil {
		log.Fatal(err)
	}
	return encryptedMessage
}

func decrypt(from, to string, encryptedMessage []byte) []byte {
	var crypto crypto.Crypto

	privateKeyStorage := storage.NewVirgilPrivateKeyStorage(&storage.FileStorage{})

	// prepare a user's private key
	toPrivateKey, _, err := privateKeyStorage.Load(to)
	if err != nil {
		log.Fatal(err)
	}

	cardManager := setupCardManager()
	// using cardManager search for Alice1's cards on Cards Service
	cards, err := cardManager.SearchCards(from)
	if err != nil {
		log.Fatal(err)
	}

	// decrypt with a private key and verify using one of Alice1's public keys
	decryptedMessage, err := crypto.DecryptThenVerify(encryptedMessage, toPrivateKey, cards.ExtractPublicKeys()...)
	if err != nil {
		log.Fatal(err)
	}
	return decryptedMessage
}

func registerCard(identity string) *sdk.Card {
	var crypto crypto.Crypto

	// generate a key pair
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyStorage := storage.NewVirgilPrivateKeyStorage(&storage.FileStorage{})

	// clean up storage before write
	privateKeyStorage.Delete(identity)

	// save a private key into key storage
	err = privateKeyStorage.Store(keypair, identity, nil)
	if err != nil {
		log.Fatal(err)
	}

	cardManager := setupCardManager()
	// publish user's on the Cards Service
	card, err := cardManager.PublishCard(&sdk.CardParams{
		PrivateKey: keypair,
		Identity:   identity,
	})
	if err != nil {
		log.Fatal(err)
	}
	return card
}

func setupCardManager() *sdk.CardManager {
	appKeyID := getEnv("TEST_APP_KEY_ID")
	appID := getEnv("TEST_APP_ID")
	appKeySource := getEnv("TEST_APP_KEY")

	var crypto crypto.Crypto
	appKey, err := crypto.ImportPrivateKey([]byte(appKeySource))
	if err != nil {
		log.Fatal(err)
	}
	return sdk.NewCardManager(session.NewGeneratorJwtProvider(session.JwtGenerator{
		AppKeyID: appKeyID,
		AppKey:   appKey,
		AppID:    appID,
	}))
}

func getEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalln(name, "environment variable is required")
	}
	return v
}
