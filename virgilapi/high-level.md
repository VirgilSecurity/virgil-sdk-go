# Initialization

Initialize high-level SDK with only application access token

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

Load key from file
```go
key, err :=ioutil.ReadFile("mykey.key")
```

Or from base64 string
```go
key, err := virgilapi.BufferFromBase64String(appPrivateKey)
```

This works too, for base64 encoded Der keys
```go
key := virgilapi.BufferFromString(appPrivateKey)
```

Initialize high-level SDK using context class

```go
api, err := virgilapi.NewWithConfig(virgilapi.Config{
        Token: "AT.[YOUR_ACCESS_TOKEN_HERE]",
        Credentials: &virgilapi.AppCredentials{
            AppId:      appCardID,
            PrivateKey: virgilapi.BufferFromString(appPrivateKey),
            PrivateKeyPassword: "YOUR_PASSWORD"
        },
        CardVerifiers: map[string]virgilapi.Buffer{
            cardServiceID: virgilapi.BufferFromString(cardsServicePublicKey),
        },
    })

```

# Register Global Virgil Card

```go
// initialize Virgil's high-level instance.
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")

// generate and save alice's Key.
aliceKey, err := api.Keys.Generate()

err = aliceKey.Save("[KEY_NAME]", "[KEY_PASSWORD]")

// create alice's Card using her newly generated Key.
aliceCard, err := api.Cards.CreateGlobal("alice@virgilsecurity.com", aliceKey)

// initiate an identity verification process.
attempt, err := aliceCard.VerifyIdentity()

// confirm a Card's identity using confirmation code retrived on the email.
token, err := attempt.Confirm("[CONFIRMATION_CODE]")

// publish a Card on the Virgil Security services.
aliceCard, err = api.Cards.PublishGlobal(aliceCard, token)

```

# Revoke Global Virgil Card

```go 
// initialize Virgil SDK high-level
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")

// load alice's Key from secure storage provided by default.
aliceKey, err = api.Keys.Load("[KEY_NAME]", "[KEY_PASSWORD]")

// load alice's Card from Virgil Security services.
aliceCard, err = api.Cards.Get("[ALICE_CARD_ID]")

// initiate Card's identity verification process.
attempt, err = aliceCard.VerifyIdentity()

token, err = attempt.Confirm("[CONFIRMATION_CODE]")

// revoke Virgil Card from Virgil Security services.
err = api.Cards.RevokeGlobal(aliceCard, virgil.RevocationReason.Unspecified, aliceKey, token)
```

# Register Local Virgil Card

### Generate user's Key and create a Card

```go
// initialize Virgil SDK
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")

// generate and save alice's Key.
aliceKey, err := api.Keys.Generate()

err = aliceKey.Save("[KEY_NAME]", "[KEY_PASSWORD]")

// create alice's Card using her Key
aliceCard, err := api.Cards.Create("alice", aliceKey, nil)
```
### Transmit a Virgil Card
Transmit alice's Card to the server side where it will be signed, validated and published on the Virgil service. 

```go
// export alice's Card to string
exportedAliceCard, err := aliceCard.Export()
```

### Publish a Virgil Card

```go
// initialize Virgil SDK high-level instance.
api, err := virgilapi.NewWithConfig(virgilapi.Config{
        Token: "AT.[YOUR_ACCESS_TOKEN_HERE]",
        Credentials: &virgilapi.AppCredentials{
            AppId:      appCardID,
            PrivateKey: virgilapi.BufferFromString(appPrivateKey),
        },
    })

// import alice's Card from its string representation.
aliceCard, err := api.Cards.Import(exportedAliceCard)

// verify alice's Card information before publishing it on the Virgil services.

// aliceCard.Identity
// aliceCard.IdentityType
// aliceCard.Data
// aliceCard.Info

// publish alice's Card on Virgil Services
publishedCard, err := api.Cards.Publish(aliceCard)
```

# Revoke Local Virgil Card

```go
// initialize Virgil SDK high-level instance.
api, err := virgilapi.NewWithConfig(virgilapi.Config{
        Token: "AT.[YOUR_ACCESS_TOKEN_HERE]",
        Credentials: &virgilapi.AppCredentials{
            AppId:      appCardID,
            PrivateKey: virgilapi.BufferFromString(appPrivateKey),
        },
    })

// get alice's Card by ID
aliceCard, err := api.Cards.Get("[ALICE_CARD_ID]")

// revoke alice's Card from Virgil Security services.
err = api.Cards.Revoke(aliceCard)
```
# Encryption

### Initialization

```go
// initialize Virgil SDK
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

### Encrypt data

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")

// search for alice's and bob's Cards
recipients, err := api.Cards.Find("alice", "bob")

message := virgilapi.BufferFromString("Hello Guys, let's get outta here.")

// encrypt message for multiple recipients
cipherData, err := recipients.Encrypt(message)

transferData := cipherData.ToBase64String()
// transferData := cipherData.ToHEXString()
```

### Decrypt data 

```go
// load alice's Key from secure storage provided by default.
aliceKey, err := api.Keys.Load("[KEY_NAME]", "[KEY_PASSWORD]")

// get buffer from base64 encoded string
encryptedData, err := virgilapi.BufferFromBase64String(transferData)

// decrypt message using alice's Private key.
originalData, err := aliceKey.Decrypt(encryptedData)
// originalData = aliceKey.Decrypt(encryptedData)

originalMessage := originalData.ToString()
// originalMessage := originalData.ToHEXString()
// originalMessage := originalData.ToBase64String()
```

# Authenticated Encryption
Authenticated Encryption provides both data confidentiality and data integrity assurances to the information being protected.

### Initialization

```go
// initialize Virgil SDK
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

### Sign then Encrypt Data

```go
// load alice's key pair from secure storage defined by default
aliceKey, err  := api.Keys.Load("[KEY_NAME]", "[KEY_PASSWORD]")

// search for bob's and chris' Cards
recipients, err := api.Cards.Find("bob", "chris")

message := virgilapi.BufferFromString("Hello Guys, let's get outta here.")

// encrypt and sign message for multiple recipients
cipherData, err := aliceKey.SignThenEncrypt(message, recipients...)

transferData := cipherData.ToString()
```

### Decrypt then Verify Data

```go
// load bob's Key from secure storage defined by default
bobKey, err := api.Keys.Load("[KEY_NAME]", "[KEY_PASSWORD]")

// search for alice's Card
aliceCards, err := api.Cards.Find("alice")
aliceCard := aliceCards[0] //or whatever filter you like

// get buffer from base64 encoded string
encryptedData, err := virgilapi.BufferFromBase64String(transferData)

// decrypt cipher message bob's key pair and verify it using alice's Card
originalData, err := bobKey.DecryptThenVerify(encryptedData, aliceCard)

originalMessage := originalData.ToString()
```

# Generating and Verifying Signatures

### Initialization

```go
// initialize Virgil SDK high-level instance
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

### Generate Digital Signature

```go
// load alice's Key from protected storage
aliceKey, err := api.Keys.Load("[KEY_NAME]", "[KEY_PASSWORD]")

message := virgilapi.BufferFromString("Hey Bob, hope you are doing well.")

// generate signature of message using alice's key pair
signature, err := aliceKey.Sign(message)
transferData := signature.ToBase64String()
```

### Validate Digital Signature

```go
// search for alice's Card
aliceCards, err := api.Cards.Find("alice")
aliceCard := aliceCards[0] //or whatever filter you like

res, err := aliceCard.Verify(message, signature)
if !res {
    ...
}
```