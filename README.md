# Virgil Security Go SDK
[Installation](#installation) | [Initialization](#initialization) | [Encryption / Decryption Example](#encryption) | [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few steps you can encrypt communication, securely store data, provide passwordless authentication, and ensure data integrity.

To initialize and use Virgil SDK, you need to have [Developer Account](https://developer.virgilsecurity.com/account/signin).

## Installation

The package is available for Go 1.7.1 and newer.

Installing the package using Package Manager Console

```
go get -u gopkg.in/virgil.v4
```


## Initialization

Be sure that you have already registered at the [Dev Portal](https://developer.virgilsecurity.com/account/signin) and created your application.

To initialize the SDK at the __Client Side__ you need only the __Access Token__ created for a client at [Dev Portal](https://developer.virgilsecurity.com/account/signin). The Access Token helps to authenticate client's requests.

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

To initialize the SDK at the __Server Side__ you need the application credentials (__Access Token__, __App ID__, __App Key__ and __App Key Password__) you got during Application registration at the [Dev Portal](https://developer.virgilsecurity.com/account/signin).

```go
keyfile, err := ioutil.ReadFile("[YOUR_APP_KEY_FILEPATH_HERE]")

api, err := virgilapi.NewWithConfig(virgilapi.Config{
        Token: "[YOUR_ACCESS_TOKEN_HERE]",
        Credentials: &virgilapi.AppCredentials{
            AppId:      "[YOUR_APP_ID_HERE]",
            PrivateKey: keyfile,
            PrivateKeyPassword : "[YOUR_APP_KEY_PASSWORD_HERE]",
        },
    })
```

## Encryption / Decryption Example

Virgil Security simplifies adding encryption to any application. With our SDK you may create unique Virgil Cards for your all users and devices. With users' Virgil Cards, you can easily encrypt any data at Client Side.


```go
// find Alice's Card(s) at Virgil Services
aliceCards, err := api.Cards.Find("alice")

// encrypt the message using Alice's Virgil Cards
message := virgilapi.BufferFromString("Hello Alice!")
cipherData, err := aliceCards.Encrypt(message)

//transmit the message using your preferred technology to Alice
transmit(cipherData.ToBase64String())
```
Alice uses her Virgil Private Key to decrypt the encrypted message.

```go
// load Alice's Virgil Key from secure storage provided by default.
aliceKey, err := api.Keys.Load("alice_key_1", "mypassword")

// get buffer from base64 encoded string
encryptedData, err := virgilapi.BufferFromBase64String(transferData)

// decrypt message using Alice's Virgil key.
originalData, err := aliceKey.Decrypt(encryptedData)

// originalData = aliceKey.Decrypt(encryptedData)
originalMessage := originalData.ToString()
```

__Next:__ On the page below you can find configuration documentation and the list of our guides and use cases where you can see appliance of Virgil Go SDK.


## Documentation

Virgil Security has a powerful set of APIs and the documentation to help you get started:

* [Get Started](/docs/get-started) documentation
  * [Encrypted storage](/docs/get-started/encrypted-storage.md)
  * [Encrypted communication](/docs/get-started/encrypted-communication.md)
  * [Data integrity](/docs/get-started/data-integrity.md)
* [Guides](/docs/guides)
  * [Virgil Cards](/docs/guides/virgil-card)
  * [Virgil Keys](/docs/guides/virgil-key)
  * [Encryption](/docs/guides/encryption)
  * [Signature](/docs/guides/signature)
* [Configuration](/docs/guides/configuration)
  * [Set Up Client Side](/docs/guides/configuration/client-configuration.md)
  * [Set Up Server Side](/docs/guides/configuration/server-configuration.md)


## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email][support].

[support]: mailto:support@virgilsecurity.com
