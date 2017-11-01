# Exporting Virgil Key

This guide shows how to export a **Virgil Key** to the string representation.

Set up your project environment before you begin to export a Virgil Key, with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To export the Virgil Key:

- Initialize **Virgil SDK**

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```


- Alice Generates a Virgil Key
- After Virgil Key generated, developers can export Alice's Virgil Key to a Base64 encoded string

```go
// generate a new Virgil Key
aliceKey,err := api.Keys.Generate()

// export the Virgil Key
exportedAliceKeyBuf, err := aliceKey.Export("[OPTIONAL_KEY_PASSWORD]")

exportedAliceKey :=  exportedAliceKeyBuf.ToBase64String()
```


Developers also can extract Public Key from a Private Key using the Virgil CLI.
