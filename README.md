# Go SDK Programming Guide

Welcome to the Go Programming Guide This guide is a practical introduction to creating apps that make use of Virgil Security features. The code examples in this guide are written in Go language.

In this guide you will find code for every task you need to implement in order to create an application using Virgil Security. It also includes a description of the main classes and methods. The aim of this guide is to get you up and running quickly. You should be able to copy and paste the code provided into your own apps and use it with minumal changes.

## Table of Contents

* [Setting up your project](#setting-up-your-project)
* [User and App Credentials](#user-and-app-credentials)
* [Creating a Virgil Card](#creating-a-virgil-card)
* [Search for Virgil cards](#search-for-virgil-cards)
* [Getting a Virgil Card](#getting-a-virgil-card)
* [Validating Virgil cards](#validating-virgil-cards)
* [Revoking a Virgil Card](#revoking-a-virgil-card)
* [Operations with Crypto Keys](#operations-with-crypto-keys)
  * [Generate Keys](#generate-keys)
  * [Import and Export Keys](#import-and-export-keys)
* [Encryption and Decryption](#encryption-and-decryption)
  * [Encrypt Data](#encrypt-data)
  * [Decrypt Data](#decrypt-data)
* [Generating and Verifying Signatures](#generating-and-verifying-signatures)
  * [Generating a Signature](#generating-a-signature)
  * [Verifying a Signature](#verifying-a-signature)
* [Authenticated encryption](#authenticated-encryption)
* [Fingerprint Generation](#fingerprint-generation)
* [High level Api](high-level.md)
* [Release Notes](#release-notes)

## Setting up your project

The Virgil SDK is provided as a package named *virgil*. The package is distributed via github.

### Prerequisites

* Go 1.7.1 or newer

### Installing the package

1. go get -u gopkg.in/virgil.v4

## User and App Credentials

When you register an application on the Virgil developer's [dashboard](https://developer.virgilsecurity.com/dashboard), we provide you with an *appID*, *appKey* and *accessToken*.

* **appID** uniquely identifies your application in our services, it is also used to identify the Public key generated in a pair with *appKey*, for example: ```af6799a2f26376731abb9abf32b5f2ac0933013f42628498adb6b12702df1a87```
* **appKey** is a Private key that is used to perform creation and revocation of *Virgil cards* (Public key) in Virgil services. Also the *appKey* can be used for cryptographic operations to take part in application logic. The *appKey* is generated at the time of creation application and has to be saved in secure place.
* **accessToken** is a unique string value that provides an authenticated secure access to the Virgil services and is passed with each API call. The *accessToken* also allows the API to associate your app’s requests with your Virgil developer’s account.

## Connecting to Virgil
Before you can use any Virgil services features in your app, you must first initialize ```virgil.Client``` class. You use the ```virgil.Client``` object to get access to Create, Revoke and Search for *Virgil cards* (Public keys).

### Initializing an API Client

To create an instance of *virgil.Client* class, just call virgil.NewClient() with your application's *accessToken* which you generated on developer's dashboard.


```go
client := virgil.NewClient("[YOUR_ACCESS_TOKEN_HERE]")
```

you can also customize initialization using your own parameters
> import "gopkg.in/virgil.v4/transport/virgilhttp"

```go
client, err := virgil.NewClient("[YOUR_ACCESS_TOKEN_HERE]",
  virgil.ClientTransport(virgilhttp.NewTransportClient("https://cards.virgilsecurity.com", "https://cards-ro.virgilsecurity.com")),
  virgil.ClientCardsValidator(virgil.NewCardsValidator()))

```

### Initializing Crypto
The *VirgilCrypto* class provides cryptographic operations in applications, such as hashing, signature generation and verification, and encryption and decryption.

```go
crypto := virgil.Crypto()
```

## Creating a Virgil Card

A *Virgil Card* is the main entity of the Virgil services, it includes the information about the user and his public key. The *Virgil Card* identifies the user/device by one of his types.

Collect an *appID* and *appKey* for your app. These parametes are required to create a Virgil Card in your app scope.

```go
appID := "[YOUR_APP_ID_HERE]"
appKeyPassword := "[YOUR_APP_KEY_PASSWORD_HERE]"
appKeyData, err := ioutil.ReadFile("[YOUR_APP_KEY_PATH_HERE]")

appKey, err := crypto.ImportPrivateKey(appKeyData, appKeyPassword)
```
Generate a new Public/Private keypair using an instance of *virgil.Crypto* class.

```go
aliceKeys, err := crypto.GenerateKeypair()
```
Prepare request
```go
//only the public key will be used from aliceKeys
createReq, err := virgil.NewCreateCardRequest("alice", "username", aliceKeys.PublicKey(), virgil.CardParams{
  Scope: virgil.CardScope.Application,
  Data: map[string]string{
    "os": "macOS",
  },
  DeviceInfo: virgil.DeviceInfo{
    Device:     "iphone7",
    DeviceName: "my iphone",
  },
})

// short version
createReq, err := virgil.NewCreateCardRequest("alice", "username", aliceKeys.PublicKey(), virgil.CardParams{})
```

then, use *RequestSigner* class to sign request with owner and app keys.

```go
requestSigner := virgil.RequestSigner{}

err = requestSigner.SelfSign(CardModel, aliceKeys.PrivateKey())
err = requestSigner.AuthoritySign(CardModel, appID, appKey)
```
Publish a Virgil Card
```go
aliceCard, err := virgil.CreateCard(CardModel)
```

## Search for Virgil cards
Performs the `Virgil Card`s search by criteria:
- the *Identities* request parameter is mandatory;
- the *IdentityType* is optional and specifies the *IdentityType* of a `Virgil Card`s to be found;
- the *Scope* optional request parameter specifies the scope to perform search on. Either 'global' or 'application'. The default value is 'application';

```go
criteria := virgil.Criteria{
		Scope:virgil.CardScope.Global,
		IdentityType:"application",
		Identities: []string{"com.virgilsecurity.cards"},
	}

	client := virgil.NewClient("[YOUR_ACCESS_TOKEN_HERE]")

	cards, err := client.SearchCards(criteria)
```

## Getting a Virgil Card
Gets a `Virgil Card` by ID.

```go
client := virgil.NewClient("[YOUR_ACCESS_TOKEN_HERE]")
card, err := client.GetCard("CARD_ID")
```

## Validating Virgil cards
This sample uses *built-in* ```CardValidator``` to validate cards. By default ```CardValidator``` validates only *cards Service* signature.

```go
// Initialize crypto API
crypto := virgil.Crypto()

validator := virgil.NewCardsValidator()

// Your can also add another Public Key for verification.
// validator.AddVerifier("[HERE_VERIFIER_CARD_ID]", [HERE_VERIFIER_PUBLIC_KEY])

// Initialize service client
    client := virgil.NewClient("[YOUR_ACCESS_TOKEN_HERE]",virgil.ClientCardsValidator(validator))
    client.SetCardsValidator(validator)

    criteria := virgil.SearchCriteriaByIdentities("alice", "bob")
    cards, err := client.SearchCards(criteria)
```

## Revoking a Virgil Card
Initialize required components.
```go
client := virgil.NewClient("[YOUR_ACCESS_TOKEN_HERE]")
crypto := virgil.Crypto()

requestSigner := &virgil.RequestSigner{}
```

Collect *App* credentials
```go
appID := "[YOUR_APP_ID_HERE]"
appKeyPassword := "[YOUR_APP_KEY_PASSWORD_HERE]"
appKeyData, err := ioutil.ReadFile("[YOUR_APP_KEY_PATH_HERE]")

appKey, err := crypto.ImportPrivateKey(appKeyData, appKeyPassword)
```

Prepare revocation request
```go
cardId := "[YOUR_CARD_ID_HERE]"

revokeRequest := virgil.NewRevokeCardRequest(cardId, enums.RevocationReason.Unspecified)
requestSigner.AuthoritySign(revokeRequest, appID, appKey)

err = client.RevokeCard(revokeRequest)
```

## Operations with Crypto Keys

### Generate Keys
The following code sample illustrates keypair generation. The default algorithm is ed25519

```go
 aliceKeys, err := crypto.GenerateKeypair()
```

### Import and Export Keys
You can export and import your Public/Private keys to/from supported wire representation.

To export Public/Private keys, simply call one of the Export methods:

```go
 exportedPrivateKey, err := crypto.ExportPrivateKey(aliceKeys.PrivateKey(), "[YOUR_PASSWORD]")
 exportedPublicKey, err := crypto.ExportPublicKey(aliceKeys.PublicKey())
```

 To import Public/Private keys, simply call one of the Import methods:

 ```go
 privateKey, err := crypto.ImportPrivateKey(exportedPrivateKey, "[YOUR_PASSWORD]")
 publicKey, err := crypto.ImportPublicKey(exportedPublicKey)
```

## Encryption and Decryption

Initialize Crypto API and generate keypair.
```go
 crypto := virgil.Crypto()
 aliceKeys, err := crypto.GenerateKeypair()
```

### Encrypt Data
Data encryption using ECIES scheme with AES-GCM. You can encrypt either stream or a byte array.
There also can be more than one recipient

*Byte Array*
```go
plaintext := []byte("Hello Bob!")
cipherData, err := crypto.Encrypt(plaintext, aliceKeys.PublicKey())
```

*Stream*
```go
	inputStream, err := os.Open(`[YOUR_FILE_PATH_HERE]`)

	if(err != nil){
		panic(err)
	}
	defer inputStream.Close()

	cipherStream, err := os.Create(`[YOUR_FILE_PATH_HERE]`)

	if(err != nil){
		panic(err)
	}
	defer cipherStream.Close()

	err = crypto.EncryptStream(inputStream, cipherStream, aliceKeys.PublicKey())
```

### Decrypt Data
You can decrypt either stream or a byte array using your private key

*Byte Array*
```go
//aliceKeys must contain private key
 crypto.Decrypt(cipherData, aliceKeys.PrivateKey())
```

 *Stream*
```go
    crypto := virgil.Crypto()

	cipherStream, err := os.Open(`[YOUR_FILE_PATH_HERE]`)

	if(err != nil){
		panic(err)
	}
	defer cipherStream.Close()

	resultStream, err := os.Create(`[YOUR_FILE_PATH_HERE]`)

	if(err != nil){
		panic(err)
	}
	defer resultStream.Close()

	err = crypto.DecryptStream(cipherStream, resultStream, aliceKeys.PrivateKey())
```

## Generating and Verifying Signatures
This section walks you through the steps necessary to use the *VirgilCrypto* to generate a digital signature for data and to verify that a signature is authentic.

Generate a new Public/Private keypair and *data* to be signed.

```go
crypto := virgil.Crypto()
aliceKeys, err := crypto.GenerateKeypair()

// The data to be signed with alice's Private key
data = []byte("Hello Bob, How are you?")
```

### Generating a Signature

Sign the SHA-384 fingerprint of either stream or a byte array using your private key. To generate the signature, simply call one of the sign methods:

*Byte Array*
```go
signature, err := crypto.Sign(data, aliceKeys.PrivateKey())
```
*Stream*
```go
inputStream, err := os.Open(`[YOUR_FILE_PATH_HERE]`)

	if(err != nil){
		panic(err)
	}
	defer inputStream.Close()

	signature, err := crypto.Sign(inputStream, aliceKeys.PrivateKey())
```
### Verifying a Signature

Verify the signature of the SHA-384 fingerprint of either stream or a byte array using Public key. The signature can now be verified by calling the verify method:

*Byte Array*

```go
 isValid, err := crypto.Verify(data, signature, aliceKeys.PublicKey())
 ```

 *Stream*

 ```go
inputStream, err := os.Open(`[YOUR_FILE_PATH_HERE]`)

	if(err != nil){
		panic(err)
	}
	defer inputStream.Close()

    isValid, err := crypto.VerifyStream(inputStream, signature, aliceKeys.PublicKey())
```

## Authenticated Encryption
Authenticated Encryption provides both data confidentiality and data integrity assurances to the information being protected.

```go
crypto := virgil.Crypto()
aliceKeys, err := crypto.GenerateKeypair()
bobKeys, err := crypto.GenerateKeypair()

// The data to be signed with alice's Private key
data = []byte("Hello Bob, How are you?")
```

### Sign then Encrypt
```go
ciphertext, err := crypto.SignThenEncrypt(data, aliceKeys.PrivateKey(), bobKeys.PublicKey())
```

### Decrypt then Verify
```go
plaintext, err := crypto.DecryptThenVerify(data, bobKeys.PrivateKey(), aliceKeys.PublicKey());
```

## Fingerprint Generation
The default Fingerprint algorithm is SHA-256.
```go
crypto := virgil.Crypto()
fingerprint := crypto.CalculateFingerprint(content)
```

## Release Notes
 - Please read the latest note here: [https://github.com/VirgilSecurity/virgil-sdk-go/releases](https://github.com/VirgilSecurity/virgil-sdk-go/releases)
