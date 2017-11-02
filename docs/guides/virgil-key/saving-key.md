# Saving Key

This guide shows how to save a **Virgil Key** from the default storage after its [generation](/docs/guides/virgil-key/generating-key.md).

Before you begin to generate a Virgil Key, set up your project environment with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To save the Virgil Key, we need to:

- Initialize the **Virgil SDK**:

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

- Save Alice's Virgil Key in the protected storage on the device

```go
// save Virgil Key into storage
err := aliceKey.Save("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")
```

Developers can also change the Virgil Key storage directory as needed, during Virgil SDK initialization.
