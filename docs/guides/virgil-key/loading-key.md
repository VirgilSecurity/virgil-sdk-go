# Loading Key

This guide shows how to load a private **Virgil Key**, which is stored on the device. The key must be loaded when Alice wants to **sign** some data, **decrypt** any encrypted content, and perform cryptographic operations.

Before loading a Virgil Key, set up your project environment with the [getting started](https://github.com/VirgilSecurity/virgil-go-php/blob/docs-review/docs/guides/configuration/client-configuration.md) guide.

To load the Virgil Key from the default storage:

- Initialize the **Virgil SDK**

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```


- Alice has to load her Virgil Key from the protected storage and enter the Virgil Key password:

```go
// load a Virgil Key from storage
aliceKey, err := api.Keys.Load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]")
```

To load a Virgil Key from a specific storage, developers need to change the storage path during Virgil SDK initialization.
