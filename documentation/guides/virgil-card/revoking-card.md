# Revoking Card

This guide shows how to revoke a **Virgil Card** from Virgil Services.

Set up your project environment before you begin to revoke a Virgil Card, with the [getting started](/documentation/guides/configuration/client-configuration.md) guide.

In order to revoke a Virgil Card, we need to:

- Initialize the **Virgil SDK** and enter Application **credentials** (**App ID**, **App Key**, **App Key password**)

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

- Get Alice's Virgil Card by **ID** from **Virgil Services**
- Revoke Alice's Virgil Card from Virgil Services

```go
// get a Virgil Card by ID
aliceCard, err := api.Cards.Get("[USER_CARD_ID_HERE]")

// revoke a Virgil Card
err = api.Cards.Revoke(aliceCard, virgil.RevocationReason.Unspecified)
```
