# Encrypted Storage
[Set Up Server](#head1) | [Set Up Clients](#head2) | [Register Users](#head3) | [Encrypt Data](#head4) | [Decrypt Data](#head5)

You may encrypt data for secure storage in the Cloud in a few steps. In this tutorial, we show a user how to fully (end-to-end) **encrypt** data.

Privacy is even more important when it comes to cloud-based storage. If servers ever get hacked, it is necessary to know the files are safe.
Virgil Security gives developers open source API with the full cycle of data security that supports almost every platform and language.


## <a name="head1"></a> Set Up Server
Your server should be able to authorize your users, store Application's Virgil Key and use **Virgil SDK** for cryptographic operations or for some requests to Virgil Services. You can configure your server using the [Setup Guide](/docs/guides/configuration/server-configuration.md).


## <a name="head2"></a> Set Up Clients
Set up the client side. After users register at your Application Server, provide them with an access token that authenticates users for further operations and transmit their **Virgil Cards** to the server. Configure the client side using the [Setup Guide](/docs/guides/configuration/client-configuration.md).


## <a name="head3"></a> Register Users
Now you need to register the users who will encrypt data.

In order to encrypt a data each user must have his own tools, which allow him to perform cryptographic operations, and these tools must contain the necessary information to identify users. In Virgil Security, these tools are the Virgil Key and the Virgil Card.

![Virgil Card](/docs/img/Card_introduct.png "Create Virgil Card")

When we have already set up the Virgil SDK on the server & client sides, we can finally create Virgil Cards for the users and transmit the Cards to your Server for further publication on Virgil Services.


### Generate Keys and Create Virgil Card
Use the Virgil SDK on the client side to generate a new Key Pair, and then create a user's Virgil Card using the recently generated Virgil Key. All keys are generated and stored on the client side.

In this example, we will pass on the user's username and a password, which will lock in their private encryption key. Each Virgil Card is signed by a user's Virgil Key, which guarantees the Virgil Card content integrity over its life cycle.

```go
// generate a new Virgil Key
aliceKey, err := api.Keys.Generate()

// save the Virgil Key into storage
err = aliceKey.Save("[KEY_NAME]", "[KEY_PASSWORD]")

// create a Virgil Card
aliceCard, err := api.Cards.Create("alice", aliceKey, nil/* custom fields */)
```


**Warning**: Virgil doesn't keep a copy of your Virgil Key. If you lose a Virgil Key, there is no way to recover it.

It should be noted that recently created user Virgil Cards will be visible only for application users because they are related to the Application.

Read more about Virgil Cards and their types [here](/docs/guides/virgil-card/creating-card.md).


### Transmit the Cards to Your Server

Next, you must serialize and transmit this Card to your server, where you will approve and publish users' Cards.

```go
// export a Virgil Card to string
exportedCard, err := aliceCard.Export()

// transmit the Virgil Card to the server
TransmitToServer(exportedCard)
```

Use the [approve & publish users guide](https://github.com/go-virgil/virgil/blob/docs-review/docs/guides/configuration/server-configuration.md#-approve--publish-cards) to publish user's Virgil Card on Virgil Services.


## <a name="head4"></a> Encrypt Data

With the Virgil Card created, we're ready to start encrypting data which will then be stored in the encrypted storage. In this case we will encrypt some data for Alice, using her own Virgil Card.

![encrypted storage](/docs/img/encrypted_storage_upload.png "Encrypt data")

In order to encrypt data, the user must search for Virgil Cards at Virgil Services, where all Virgil Cards are saved.

```go
// search for Virgil Cards
aliceCards, err := api.Cards.Find("alice")

fileBuf := virgilapi.BufferFromString("[FILE_CONTENT]")

// encrypt the buffer using found Virgil Cards
cipherFileBuf, err := aliceCards.Encrypt(fileBuf)
```

See our [guide](/docs/guides/virgil-card/finding-card.md) on Finding Cards for best practices on loading Alice's card.

### Storage

With this in place, Alice is now ready to store the encrypted files to a local or remote disk (Clouds).


## <a name="head5"></a> Decrypt Data

You can easily **decrypt** your encrypted files at any time using your private Virgil Key.

![Encrypt Data](/docs/img/encrypted_storage_download.png "Decrypt Data")

To decrypt your encrypted files, load the data and use your own Virgil Key to decrypt the data.

```go
// load a Virgil Key from device storage
aliceKey, err := api.Keys.Load("[KEY_NAME]", "[KEY_PASSWORD]")

// decrypt a cipher buffer using loaded Virgil Key
originalFileBuf, err := bobKey.Decrypt(cipherFileBuf)
```

To decrypt data, you will need your stored Virgil Key. See the [Loading Key](/docs/guides/virgil-key/loading-key.md) guide for more details.
