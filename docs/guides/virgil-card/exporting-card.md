# Exporting Card

This guide shows how to export a **Virgil Card** to the string representation.

Before you begin to export a Virgil Card, set up your project environment with the [getting started](/docs/guides/configuration/client-configuration.md) guide.

To export a Virgil Card, we need to:

- Initialize the **Virgil SDK**

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

- Use the code below to export the Virgil Card to its string representation.

```go
  exportedAliceCard, err := aliceCard.Export()
```

The same mechanism works for **Global Virgil Card**.
