# Virgil Security Go SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-sdk-go.png?branch=v5)](https://travis-ci.com/VirgilSecurity/virgil-sdk-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)



## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- communicate with [Virgil Cards Service][_cards_service]
- manage users' Public Keys
- store private keys in secure local storage
- use Virgil [Crypto library][_virgil_crypto]
- use your own Crypto


## Installation

The Virgil Go SDK is provided as a package named virgil. The package is distributed via github. Also in this guide, you find one more package called Virgil Crypto (Virgil Crypto Library) that is used by the SDK to perform cryptographic operations.

The package is available for Go 1.12 or newer.

Installing the package:

- go get -u github.com/VirgilSecurity/virgil-sdk-go/sdk

### Virgil Crypto Library

Virgil crypto library is a wrapper on [C crypto library](https://github.com/VirgilSecurity/virgil-crypto-c). Virgil crypto library use prebuild C library for better experience for most popular operation system:

- MacOS amd64 with X Code 11
- Windows amd64 with mingw64
- Linux amd64 gcc >= 5 and clang >=7
- For support older version linux amd64 gcc < 5 and clang < 7  with 2.14 Linux kernel use tag `legacy_os`

## Library purposes
* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)

## Usage Examples

Before start practicing with the usage examples be sure that the SDK is configured. Check out our [SDK configuration guides][_configure_sdk] for more information.

#### Generate and publish user's Cards with Public Keys inside on Cards Service
Use the following lines of code to create and publish a user's Card with Public Key inside on Virgil Cards Service:

```go
import (
	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/sdk"
	"github.com/VirgilSecurity/virgil-sdk-go/session"
	"github.com/VirgilSecurity/virgil-sdk-go/storage"
)

var (
	AppKey   = "{YOUR_APP_KEY}"
	AppKeyID = "{YOUR_APP_KEY_ID}"
	AppID    = "{YOU_APP_ID}"
)

func main() {
	var crypto crypto.Crypto
	const identity = "Alice"

	// generate a key pair
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		//handle error
	}

	privateKeyStorage := storage.NewVirgilPrivateKeyStorage(&storage.FileStorage{})
	// save a private key into key storage
	err = privateKeyStorage.Store(keypair, identity, nil)
	if err != nil {
		//handle error
	}

	appKey, err := crypto.ImportPrivateKey([]byte(AppKey))
	if err != nil {
		//handle error
	}

	cardManager := sdk.NewCardManager(session.NewGeneratorJwtProvider(session.JwtGenerator{
		AppKeyID: AppKeyID,
		AppKey:   appKey,
		AppID:    AppID,
	}))

	// publish user's on the Cards Service
	card, err := cardManager.PublishCard(&sdk.CardParams{
		PrivateKey: keypair,
		Identity:   identity,
	})
	if err != nil {
		//handle error
	}
}
```

#### Sign then encrypt data

Virgil SDK lets you use a user's Private key and his or her Cards to sign, then encrypt any kind of data.

In the following example, we load a Private Key from a customized Key Storage and get recipient's Card from the Virgil Cards Services. Recipient's Card contains a Public Key on which we will encrypt the data and verify a signature.

```go
import (
	"github.com/VirgilSecurity/virgil-sdk-go/sdk"
	"github.com/VirgilSecurity/virgil-sdk-go/sdk/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/sdk/storage"
)


func main() {
	var crypto crypto.Crypto
	messageToEncrypt := []byte("Hello, Bob!")

	privateKeyStorage := storage.NewVirgilPrivateKeyStorage(&storage.FileStorage{})

	// prepare a user's private key from a device storage
	alicePrivateKey, _, err := privateKeyStorage.Load("Alice")
	if err != nil{
		//handle error
	}

	// using cardManager search for Bob's cards on Cards Service
	cards, err := cardManager.SearchCards("Bob")
	if err != nil{
		//handle error
	}

	// sign a message with a private key then encrypt using Bob's public keys
	encryptedMessage, err := crypto.SignThenEncrypt(messageToEncrypt, alicePrivateKey, cards.ExtractPublicKeys()...)
	if err != nil{
		//handle error
	}
}

```

#### Decrypt then verify data
Once the Users receive the signed and encrypted message, they can decrypt it with their own Private Key and verify signature with a Sender's Card:

```go
import "github.com/VirgilSecurity/virgil-sdk-go/sdk/crypto"


func main() {
	var crypto crypto.Crypto

	privateKeyStorage := storage.NewVirgilPrivateKeyStorage(&storage.FileStorage{})

	// prepare a user's private key
	bobPrivateKey, err := privateKeyStorage.Load("Bob")
	if err != nil{
		//handle error
	}

	// using cardManager search for Alice's cards on Cards Service
	aliceCards, err := cardManager.SearchCards("Alice")
	if err != nil{
		//handle error
	}

	// decrypt with a private key and verify using one of Alice's public keys
	decryptedMessage, err := crypto.DecryptThenVerify(encryptedMessage, bobPrivateKey, cards.ExtractPublicKeys()...)
	if err != nil{
		//handle error
	}
}
```

## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

In order to use the Virgil SDK with your application, you will need to first configure your application. By default, the SDK will attempt to look for Virgil-specific settings in your application but you can change it during SDK configuration.

* [Configure the SDK][_configure_sdk] documentation
  * [Setup authentication][_setup_authentication] to make API calls to Virgil Services
  * [Setup Card Manager][_card_manager] to manage user's Public Keys
  * [Setup Card Verifier][_card_verifier] to verify signatures inside of user's Card
  * [Setup Key storage][_key_storage] to store Private Keys
  * [Setup your own Crypto library][_own_crypto] inside of the SDK
* [More usage examples][_more_examples]
  * [Create & publish a Card][_create_card] that has a Public Key on Virgil Cards Service
  * [Search user's Card by user's identity][_search_card]
  * [Get user's Card by its ID][_get_card]
  * [Use Card for crypto operations][_use_card]


## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.slack.com/join/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto-go/tree/master
[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v5
[_use_card]: https://developer.virgilsecurity.com/docs/go/how-to/public-key-management/v5/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/go/how-to/public-key-management/v5/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/go/how-to/public-key-management/v5/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/go/how-to/public-key-management/v5/create-card
[_own_crypto]: https://developer.virgilsecurity.com/docs/go/how-to/setup/v5/setup-own-crypto-library
[_key_storage]: https://developer.virgilsecurity.com/docs/go/how-to/setup/v5/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/go/how-to/setup/v5/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/go/how-to/setup/v5/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/go/how-to/setup/v5/setup-authentication
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management
