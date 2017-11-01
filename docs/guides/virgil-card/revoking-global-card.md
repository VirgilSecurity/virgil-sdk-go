# Revoking Global Card

This guide shows how to revoke a **Global Virgil Card**.

Set up your project environment before you begin to revoke a Global Virgil Card, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To revoke a Global Virgil Card, we need to:

-  Initialize the Virgil SDK

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

- Load Alice's **Virgil Key** from the secure storage provided by default
- Load Alice's Virgil Card from **Virgil Services**
- Initiate the Card identity verification process
- Confirm the Card identity using a **confirmation code**
- Revoke the Global Virgil Card from Virgil Services

```go
// load a Virgil Key from storage
aliceKey, err := api.Keys.Load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")

// load a Virgil Card from Virgil Services
aliceCard, err := api.Cards.Get("[USER_CARD_ID_HERE]")

// initiate an identity verification process.
attempt, err := aliceCard.VerifyIdentity()

// grab a validation token
token, err := attempt.Confirm("[CONFIRMATION_CODE]")

// revoke a Global Virgil Card
err = api.Cards.RevokeGlobal(aliceCard, virgil.RevocationReason.Unspecified, aliceKey, token)
```
