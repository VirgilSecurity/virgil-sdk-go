# Importing Card

This guide shows how to import a **Virgil Card** from the string representation.

Before you begin to import a Virgil Card, set up your project environment with the [getting started](/docs/guides/configuration/client-configuration.md) guide.


To import the Virgil Card, we need to:

- Initialize the **Virgil SDK**

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```


- Use the code below to import the Virgil Card from its string representation

```go
// import a Virgil Card from string
aliceCard, err := api.Cards.Import(exportedAliceCard)
```
