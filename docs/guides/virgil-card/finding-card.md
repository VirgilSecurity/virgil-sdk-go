# Finding Card

This guide shows how to find a **Virgil Card**. As previously noted, all Virgil Cards are saved at **Virgil Services** after their publication. Thus, every user can find their own Virgil Card or another user's Virgil Card on Virgil Services. It should be noted that users' Virgil Cards will only be visible to application users. Global Virgil Cards will be visible to anybody.

Set up your project environment before you begin to find a Virgil Card, with the [getting started](/documentation/guides/configuration/client-configuration.md) guide.


In order to search for an **Application** or **Global Virgil Card** you need to initialize the **Virgil SDK**:

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```


### Application Cards

There are two ways to find an Application Virgil Card on Virgil Services:

The first one allows developers to get the Virgil Card by its unique **ID**

```go
aliceCard, err := api.Cards.Get("[ALICE_CARD_ID]")
```

The second one allows developers to find Virgil Cards by *identity* and *identityType*

```go
// search for all User's Virgil Cards.
aliceCards, err := api.Cards.Find("alice");
```



### Global Cards

```go
// search for all Global Virgil Cards
bobGlobalCards, err := api.Cards.FindGlobal("email", "bob@virgilsecurity.com")

// search for Application Virgil Card
appCards, err := api.Cards.FindGlobal("application", "com.username.appname")
```
