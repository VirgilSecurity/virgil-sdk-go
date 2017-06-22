# Virgil Security Go SDK 

[Installation](#installation) | [Encryption Example](#encryption-example) | [Initialization](#initialization) | [Documentation](#documentation) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

For a full overview head over to our Go [Get Started][_getstarted] guides.

## Installation

Run `go get -u gopkg.in/virgil.v5`

then add import

```go
import "gopkg.in/virgil.v5"
```

__Next:__ [Get Started with the Go SDK][_getstarted].

## Encryption Example

Virgil Security makes it super easy to add encryption to any application. With our SDK you create a public [__Virgil Card__][_guide_virgil_cards] for every one of your users and devices. With these in place you can easily encrypt any data in the client.


```go
// find Alice's card(s)
aliceCards, err := api.Cards.Find("alice")

// encrypt the message using Alice's cards
message := virgilapi.BufferFromString("Hello Alice!")
cipherData, err := aliceCards.Encrypt(message)
//transmit the message using your preferred technology

transmit(cipherData.ToBase64String())
```

The receiving user then uses their stored __private key__ to decrypt the message.


```go
// load alice's Key from secure storage provided by default.
aliceKey, err := api.Keys.Load("alice_key_1", "mypassword")

virgilbuffer
encryptedData, err := virgilapi.BufferFromBase64String(transferData)

// decrypt message using alice's Private key.
originalData, err := aliceKey.Decrypt(encryptedData)
// originalData = aliceKey.Decrypt(encryptedData)

originalMessage := originalData.ToString()
```

__Next:__ To [get you properly started][_guide_encryption] you'll need to know how to create and store Virgil Cards. Our [Get Started guide][_guide_encryption] will get you there all the way.

__Also:__ [Encrypted communication][_getstarted_encryption] is just one of the few things our SDK can do. Have a look at our guides on  [Encrypted Storage][_getstarted_storage], [Data Integrity][_getstarted_data_integrity] and [Passwordless Login][_getstarted_passwordless_login] for more information.

## Initialization

To use this SDK you need to [sign up for an account](https://developer.virgilsecurity.com/account/signup) and create your first __application__. Make sure to save the __app id__, __private key__ and it's __password__. After this, create an __application token__ for your application to make authenticated requests from your clients.

To initialize the SDK on the client side you will only need the __access token__ you created.

```go
// initialize Virgil SDK
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

> __Note:__ this client will have limited capabilities. For example, it will be able to generate new __Cards__ but it will need a server-side client to transmit these to Virgil.

To initialize the SDK on the server side we will need the __access token__, __app id__ and the __App Key__ you created on the [Developer Dashboard](https://developer.virgilsecurity.com/).

```go

key, err :=ioutil.ReadFile("mykey.key")

...

api, err := virgilapi.NewWithConfig(virgilapi.Config{
        Token: "AT.[YOUR_ACCESS_TOKEN_HERE]",
        Credentials: &virgilapi.AppCredentials{
            AppId:      "[APP_CARD_ID]",
            PrivateKey: key,
            PrivateKeyPassword: "YOUR_PASSWORD"
        },
        CardVerifiers: map[string]virgilapi.Buffer{
            cardServiceID: virgilapi.BufferFromString(cardsServicePublicKey),
        },
        SkipBuiltInVerifiers: true,
    })

```

Next: [Learn more about our the different ways of initializing the .NET/C# SDK][_guide_initialization] in our documentation.

## Documentation

Virgil Security has a powerful set of APIs, and the documentation is there to get you started today.

* [Get Started][_getstarted_root] documentation
  * [Initialize the SDK][_initialize_root]
  * [Encrypted storage][_getstarted_storage]
  * [Encrypted communication][_getstarted_encryption]
  * [Data integrity][_getstarted_data_integrity]
  * [Passwordless login][_getstarted_passwordless_login]
* [Guides][_guides]
  * [Virgil Cards][_guide_virgil_cards]
  * [Virgil Keys][_guide_virgil_keys]

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email](support).

[support]: mailto:support@virgilsecurity.com
[_getstarted_root]: https://virgilsecurity.com/docs/sdk/go/
[_getstarted]: https://virgilsecurity.com/docs/sdk/go/
[_getstarted_encryption]: https://virgilsecurity.com/docs/use-cases/encrypted-communication
[_getstarted_storage]: https://virgilsecurity.com/docs/use-cases/secure-data-at-rest
[_getstarted_data_integrity]: https://virgilsecurity.com/docs/use-cases/data-verification
[_getstarted_passwordless_login]: https://virgilsecurity.com/docs/use-cases/passwordless-authentication
[_guides]: https://stg.virgilsecurity.com/docs/sdk/go/features
[_guide_initialization]: https://virgilsecurity.com/docs/sdk/go/getting-started#initializing
[_guide_virgil_cards]: https://virgilsecurity.com/docs/sdk/go/features#virgil-cards
[_guide_virgil_keys]: https://virgilsecurity.com/docs/sdk/go/features#virgil-keys
[_guide_encryption]: https://virgilsecurity.com/docs/sdk/go/features#encryption
[_initialize_root]: https://virgilsecurity.com/docs/sdk/go/programming-guide#initializing