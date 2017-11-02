# Creating Card

This guide shows how to create a user's **Virgil Card** – the main entity of **Virgil Services**. Every user or device is represented by Virgil Card with all necessary identification information.

Every developer can create a user's **Virgil Card** (visible within the Application) or **Global Virgil Card** (visible to anybody and not related to the Application).

See our [Use Cases](https://github.com/VirgilSecurity/virgil-sdk-go/tree/docs-review/docs/get-started) to find out what you can do with Virgil Cards. If you need to create a Global Virgil Card, start with the guide, [Creating a Global Card](/docs/guides/virgil-card/creating-global-card.md).

After a Virgil Card is created, it's published at Virgil Card Service, where an owner can find their Virgil Cards at any time.

**Warning**: You cannot change a Virgil Card content after it is published.

Each Virgil Card contains a  permanent digital signature that provides data integrity for the Virgil Card over its life-cycle.



### Let's start to create a user's Virgil Card

Before you begin to create a user's Virgil Card, set up your project environment with the [getting started](/docs/guides/configuration/client-configuration.md) guide.


The Virgil Card creation procedure is shown in the figure below.

![Virgil Card Generation](/docs/img/Card_introduct.png "Create Virgil Card")


To create a Virgil Card:

1. Developers need to initialize the **Virgil SDK**

```go
api, err := virgilapi.New("[YOUR_ACCESS_TOKEN_HERE]")
```

Users' Virgil Card creation is carried out on the client side.

2. Once the SDK is ready, we can proceed to the next step:
  – Generate and save a **Virgil Key** (it's also necessary to enter the Virgil Key name and password)
  – Create a Virgil Card using the recently generated Virgil Key


  ```go
  // generate a new Virgil Key
  aliceKey, err := api.Keys.Generate()

  // save the Virgil Key into the storage
  err = aliceKey.Save("[KEY_NAME]", "[KEY_PASSWORD]")

  // create a Virgil Card
  aliceCard, err := api.Cards.Create("alice", aliceKey, nil/* custom fields */)
  ```


The Virgil Key will be saved into default device storage. Developers can also change the Virgil Key storage directory as needed during Virgil SDK initialization.

**Warning**: Virgil doesn't keep a copy of your Virgil Key. If you lose a Virgil Key, there is no way to recover it.

3. Developers have to transmit the Virgil Card to the App's server side where it will be signed, validated and then published on Virgil Services (this is necessary for further operations with the Virgil Card).

```go
  exportedAliceCard, err := aliceCard.Export()
```

#{ export "import_card" }
```go
// import a Virgil Card from string
aliceCard, err := api.Cards.Import(exportedAliceCard)
```

A user's Virgil Card is related to its Application, so the developer must identify their Application.

On the Application's Server Side, one must:

 - Initialize the Virgil SDK and enter the Application **credentials** (**App ID**, **App Key**, and **App Key password**).

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


-  Import a Virgil Card from its string representation.

```go
// import a Virgil Card from string
aliceCard, err := api.Cards.Import(exportedAliceCard)
```

-  Then publish a Virgil Card on Virgil Services.

```go
err := api.Cards.Publish(aliceCard)
```

Developers also can create a Virgil Card using the Virgil CLI.
