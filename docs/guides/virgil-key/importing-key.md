# Importing Virgil Key

This guide shows how to export a **Virgil Key** from a Base64 encoded string representation.

Set up your project environment before you begin to import a Virgil Key, with the [getting started](/documentation/guides/configuration/client-configuration.md) guide.

In order to import a Virgil Key, we need to:

- Initialize **Virgil SDK**

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

- Choose a Base64 encoded string
- Import the Virgil Key from the Base64 encoded string

```go
// initialize a buffer from base64 encoded string
aliceKeyBuffer, err := virgilapi.BufferFromBase64String("[BASE64_ENCODED_VIRGIL_KEY]")

// import Virgil Key from buffer
aliceKey, err := api.Keys.Import(aliceKeyBuffer, "[OPTIONAL_KEY_PASSWORD]");
```
