Perfect Forward Secrecy module
==============================

Perfect Forward Secrecy (PFS) Is a technique, that protects previously
intercepted traffic from being decrypted even if the main private key is
compromised. 

To provide PFS, we need to be able to store **ephemeral** public keys
(cards) on server.

PREREQUISITES
=============

### Functions needed:

-   **KDF**(SK, salt, info) - generates key material based on shared
    secret **SK** and optional **salt** and **info** values.

-   **ENCRYPT**(k, n, ad, plaintext): Encrypts plaintext using the
    cipher key k and and nonce n which must be unique for the key k.
    Optional additional data **ad** can be supplied

-   **DECRYPT**(k, n, ad, ciphertext): Decrypts ciphertext using a
    cipher key k, a nonce n, and associated data **ad**. Returns the
    **plaintext**, unless authentication fails, in which case an error
    is signaled to the caller.

### Suggested primitives:

**KDF **- HKDF

**ENCRYPT/DECRYPT**- AES-GCM or Chaha20-poly1305

**HASH **- SHA256/SHA512//Blake2b

Bob side (receiver)
-------------------

Before Bob can use PFS he must do the following:

1.  Have a main (identity) Virgil card **IC<sub>B</sub>** registered at
    Virgil cloud

2.  Generate a long-term ephemeral card **LTC<sub>B</sub>**, sign it
    with the main card and post it on server

3.  Generate a set of one-time ephemeral cards **OTC<sub>B</sub>** (100
    by default), sign them with the main card and post them on server

Alice side (sender)
-------------------

1.  Have a main (identity) Virgil card **IC<sub>A </sub>**in the cloud

2.  Get Bob's identity card, long-term ephemeral card and (if exists)
    one-time ephemeral card

Protocol
========

### The set of keys used:

-   Bob's Identity card **IC<sub>B</sub>**

-   Bob's long-term ephemeral card **LTC<sub>B</sub>**

-   Bob's one-time ephemeral card **OTC<sub>B</sub>**

-   Alice's Identity card **IC<sub>A</sub>**

-   Alice's ephemeral key **EK<sub>A</sub>**  
      
      
    All public keys have a corresponding private key, but to simplify
    description we will focus on the public keys.

INITIAL PHASE
-------------

Alice calculates the following DHs:

1.  DH1 = DH(**IC<sub>A</sub>**,**LTC<sub>B</sub>**)

2.  DH2 = DH(**EK<sub>A</sub>**, **IC<sub>B</sub>**)

3.  DH3 = DH(**EK<sub>A</sub>**, **LTC<sub>B</sub>**)

4.  DH4 = DH(**EK<sub>A</sub>**, **OTC<sub>B</sub>**)

<embed src="media/image1.tmp" width="295" height="250" />

STRONG AND WEAK SESSIONS
------------------------

Strong session is formed when DH4 is present.

Strong shared secret **SKs** = **128 bytes** of **KDF** ( **DH1** ||
**DH2** || **DH3** || ***DH4***) 

Weak shared secret **SKw** = **128
bytes **of** KDF** ( **DH1** || **DH2** || **DH3)**

Following statements are common for both session types:

First 64 bytes is Alice's send/Bob's receive secret **SKa**, second 64
bytes is Alice's receive/Bob's send secret **SKb **

After calculating ***SKa, SKb***, Alice deletes her ephemeral private
key and the *DH* outputs.

Alice then calculates an "additional  data" byte sequence *AD* that
contains identity card IDs for both parties: 

**Strong session additional data**= Card IDs of (**IC<sub>A</sub> **||
**IC<sub>B</sub>** || **LTC**<sub>B</sub>  || **OTC<sub>B\\ </sub>**||
"**Virgil**")

**Weak session additional data** = Card IDs of
(**IC<sub>A</sub> **|| **IC<sub>B</sub>** || **LTC**<sub>B** **</sub>||"**Virgil**")

Alice may optionally append additional information to *AD*, such as
Alice and Bob's usernames, certificates, or other identifying
information (app decides).

To avoid situations when Bob does not have OTC key, **either weak or
both sessions **are calculated during initial phase.

Alice must store both strong & weak sessions until Bob replies with one
of them meaning he chose one.

Alice must encrypt messages with both strong & weak sessions until she
receives a response from Bob.

Alice then sends Bob an initial message containing:

-   Alice's identity CardID

-   Alice's ephemeral public key ***EK<sub>A</sub>***

-   The signature of ***EK<sub>A</sub>***

-   Card IDs of **IC<sub>B</sub>** , **LTC<sub>B</sub>**
    and **OTC<sub>B</sub>  **(if present)

-   16 bytes of random salt for **strong** session

-   16 bytes of random salt for **weak **session

-   Ciphertext, encrypted with strong session symmetric key

-   Ciphertext, encrypted with weak session symmetric key

**Sample message structure**

{

id:"230948203482",

eph: "woecwecWEcwec==",

sign: "23fFF23cswf==",

ic\_id: "239ff0239809faadd",

ltc\_id: "234234abc",

otc\_id: "2394823049820349bcd",

salt\_s: "4rqervQERVqrevwed==",

salt\_w: "ddqervQERVqrevwed==",

ciphertext\_s: "qervQERVqrevqERVqERVSfgvbwf=="

ciphertext\_w: "qervQERVqrevqERVqERVSfgvbwf=="

}

RECEIVING THE INITIAL MESSAGE
-----------------------------

Upon receiving Alice's initial message, Bob retrieves Alice's identity
card and ephemeral key from the message. Bob also loads his identity
card's private key, and the private key(s) corresponding to whichever
long-term and one-time ephemeral cards (if any) Alice used.

Using these keys, Bob repeats the DH and KDF calculations from the
previous section to derive SK, and then deletes the DH values.

Bob then constructs the AD byte sequence the same way same as Alice, as
described in the previous section. 

**Bob must use strong session if he is able to calculate it.**

GETTING RESPONSE FROM BOB
-------------------------

Upon getting response from Bob,  Alice must drop either weak or strong
session( if she had two), depending which one Bob choose

**Till that time Alice must send messages to Bob using both sessions**

**Session**
===========

Session consists of **SKa, SKb, AD**

**SessionID** is calculated as **HASH** (**SK** || **AD || "Virgil"**)
and sent along the encrypted message to identify messages from different
sessions

ENCRYPTING/DECRYPTING ACTUAL MESSAGES
=====================================

ENCRYPTING MESSAGE:
-------------------

1.  Generate 16 byte random **salt**

2.  **If Initiator == true then SK = SKa else SKb**

3.  **message\_key**, **nonce** = KDF (**SK**, **salt**, "Virgil")

4.  **ciphertext** = ENCRYPT (**message\_key, nonce, AD, plaintext)**

5.  Send **SessionID** , **salt**, **ciphertext**

**Multiple messages can be sent at once, for different sessions**

**Sample message structure**

\[

{

session\_id: "000qervQERVqrevqEwweRVqERVSfgvbwf==",

salt: "qervQERVqrevwed==",

ciphertext:
"qervQERVqrevqEwef23f23f23fefwefFFFwef3f3f2FFFwedfJj5RVqERVSfgvbwf=="

},

{

session\_id: "111qervQERVqrevqEwweRVqERVSfgvbwf==",

salt: "qervQERVqrevwed==",

ciphertext:
"qervQERVqrevqEwef23f23f23fefwefFFFwef3f3f2FFFwedfJj5RVqERVSfgvbwf=="

}

\]

DECRYPTING MESSAGE:
-------------------

1.  read 16 byte **salt**

2.  **If Initiator == true then SK = SKb else SKa**

3.  **message\_key**, **nonce** = KDF (**SK**, **salt**, "Virgil")

4.  **plaintext**= DECRYPT (**message\_key, nonce, AD, ciphertext)**

Maintaining state
=================

Bob must upload new one time ephemeral cards as soon as they get used,
maintain their amount periodically.

Also, Bob must renew his long-term ephemeral card every several days.

Crypto methods
==============

struct Session{

SKa, SKb, AD, ID \[\]byte

Initiator bool

}

struct EncryptedMessage{

SessionID, Salt, Ciphertext \[\]byte

}

func Encrypt (sess Session, plaintext \[\]byte) EncryptedMessage{

salt = random (16 bytes)

var SK \[\]byte

if sess.Initiator then SK = sess.SKa else SK = Sess.SKb

messageKey, nonce = HKDF(SK, salt, "Virgil")

ciphertext = AES-GCM(messageKey, nonce, plaintext, sess.AD)

return new EncryptedMessage{

SessionID: sess.ID,

Salt : salt,

Ciphertext: ciphertext

}

}

func Decrypt (sess Session, msg EncryptedMessage) plaintext {

var SK \[\]byte

if sess.Initiator then SK = sess.SKa else SK = Sess.SKb

messageKey, nonce = HKDF(SK, msg.Salt, "Virgil")

plaintext = AES-GCM-Decrypt(messageKey, nonce, msg.Ciphertext, sess.AD)

return plaintext

}

func StartSession (ICa, EKa PrivateKey, ICb LTCb, &lt;optional&gt; OTCb
PublicKey, additionalData \[\]byte) Session {

var sess Session

sess.Initiator = true

DH1 = DH(ICa, LTCb)

DH2 = DH(EKa, ICb)

DH3 = DH(EKa, LTCb)

if OTCb != nil{

DH4 = DH(EKa, OTCb)

SK := &lt;128 bytes of&gt; HKDF( DH1 || DH2 || DH3 || DH4)

sess.SKa = &lt;first 64 bytes of SK&gt;

sess.SKb = &lt;second 64 bytes of SK&gt;

} else {

SK = &lt;128 bytes of&gt; HKDF( DH1 || DH2 || DH3)

sess.SKa = &lt;first 64 bytes of SK&gt;

sess.SKb = &lt;second 64 bytes of SK&gt;

}

if additionalData != null{

sess.AD = HASH (additionalData)

}

sess.ID = HASH (sess.SK || sess.AD || "Virgil")

return sess

}

func ReceiveSession (ICb LTCb, &lt;optional&gt; OTCb PrivateKey, ICa,
EKa PublicKey, additionalData \[\]byte) Session {

var sess Session

sess.Initiator = false

DH1 = DH(LTCb, ICa)

DH2 = DH(ICb, EKa)

DH3 = DH(LTCb, EKa)

if OTCb != nil{

DH4 = DH(OTCb, EKa)

SK := &lt;128 bytes of&gt; HKDF( DH1 || DH2 || DH3 || DH4)

sess.SKa = &lt;first 64 bytes of SK&gt;

sess.SKb = &lt;second 64 bytes of SK&gt;

} else {

SK = &lt;128 bytes of&gt; HKDF( DH1 || DH2 || DH3)

sess.SKa = &lt;first 64 bytes of SK&gt;

sess.SKb = &lt;second 64 bytes of SK&gt;

}

if additionalData != null{

sess.AD = HASH (additionalData)

}

sess.ID = HASH (sess.SK || sess.AD || "Virgil")

return sess

}

Test Vectors
============

Case when OTC is present
------------------------

{

"AD": "jS5dniDB2RP39J2ZJjcM9JpnkX8SuoUq3CFZ1UfsL9w=",

"AdditionalData":
"6fcwLCNv7sVoFfeVOCDWGKwb+SHuHTr7YxF+iZ73UbIeRB66xd7FoubQpCDpuZ5FuaRrY9NdOMjYnAoxjFeK0VZpcmdpbA==",

"Ciphertext":
"E64U9hJzyt00LZ7cbAUkCszZMBn0MgN/3BjXGfJ3FBKCmLvmDbEZiP8ME+x+Uj+FrMY7nVvFfM7sfaOhtWU+wIUjH5LKw8WnOvxL96NAZ6baGkMvqOqx6vZVqIrvuzKwPWd6h10ZaWLXlY+4IgjU/bgtLmjkqmTosTjOvOwYm/Ij1cIclPGyEBgvc/G2H/vTQ8Ewyt354MZNj2+1s9omhanChVK+kw8hvDEcjVmVSNPcYkcXAYTd3uByJo5E9geWuMqFy9Q3Z6aW4NXmgH0Iy2BxO+yEKHSWworvi7L8ISjvVGSxIU1jdt8dHHxFBYPfGxDvtCHfaceP4SpZmjgC5vqhEckNL8Ae2onNldNZBAyvgs2aOsgsibEcoV54JH/icy0h+Ydrw945P9oXIlcsB3robhrRpON1T4P5mQhnEHsHrEovHaDvSmA09I0uhWy0X6OGq6648jQzIBgTzQ08JRxPk1uwaJwhVTbYjOzia8sqTIwyOIo8Fp6Ax3KudiJ3IziuTdVu/57jIaBhO3ta3a7p8P/o6I453q4ukVfkGSII2weIFXDxpwPO13CzM+7/M9BvYL61kNnToN6PQnxDr12XNjjlYBeqE/CgTZAtMMR1+GVIQXCOYcUjaRS2aGwufeudzd8W6hGUAiiNF/VjzmX4++ShtJdInQWatX2Q0NEhce3//mb7rh4Q1AKyACx4IsYhoTWvj2+oSfWM+ZHvW0/H6Il8cQhriHDWlkmjboD8tzLP9J509Xlh0TjbzDrd28s7HhFdonz8oTU08uJD06KJ0JyYZtoNQuy5W2g/yHq0f3LO7NO+7mXa3laTkEv0GMIIiV3/2NLQPsNzE7cpyfgkhqfpj6P218ZQ7JVoupUXORWz9BUtvTBEZz5qZKvX0VJM0PiKJlUiOrRrgMeQKrY2W08Vgd2kTwx4zqy8p2yOfkwM9ZOHSAcl8JTPeFuZjmAKiCHIQGFUqhaK9pH1NWKgjCzuw1nyg2oPQn29+fW5f5G30mP2oVxKs0ZWjFfMthE76oMiak296csg/eQFev8EwEtE+oxVqfOJuT88IlpcYhgvtIzgU1Dfu2aiJoLQQqeA2k4qfkMVtZg62rFA4++vQ4PcpIPP9/BlLbk939lOB5yGUM7H8yko8sTosl6yj7L8p88uRoDMH6C64Xgjl/OP0A91kmOJ0zpxwaJXyTRmMrGjwA8he0rfcst75t5jns82RU+bG3a9axGZdz1p9ug7jQ2meeSySLUOh2q6wk1qpJFMA91mvcjPPFyKOOgbpX01WGSICPKdueJZdNDUNMeeCL9mHaaLL4xmbn0H8iU7RudrDNKyt4bIg7NIWO8Uzf18v+QpV3l5I0vXOFzgmKZbf6vAU8YpGEv4qI+oCtML",

"EKa":
"MC4CAQAwBQYDK2VwBCIEIF7NzaPCjWGdROCSHp2QYZnyJVtEpHHyW70f6FNvaNDc",

"ICa":
"MC4CAQAwBQYDK2VwBCIEIH5Q7MmnJwX3AdyVWOOKRnvJDaScbqnJ1EDPU4wGqdZO",

"ICb":
"MC4CAQAwBQYDK2VwBCIEIB2YFtACBqF8bthE/LfGXKNrJjNboiEEzWbvy+E/y9Un",

"LTCb":
"MC4CAQAwBQYDK2VwBCIEICAvMl+FHDbOf3I7L84MiO6cAX6fUivfv8gifnKouBGU",

"OTCb":
"MC4CAQAwBQYDK2VwBCIEIHHziklca/rGPgYyw2lNeymOH3SYGBll8o2/sBTgwRFw",

"Plaintext":
"i3ltgF73VXswExnH1wlSgpbkUGmNxB2fWjHLRLDU30MwyzMXkhdtgp9clu60ygvduauKIZN5KKNnIA148aPMdkdoQCSn8nOTuDKmqW21UVg6cpGT+Kr4bCfBRju+VAKuInNiT2VUu+yOZxvtJMoqbuFxT4HIDxwrXyiCaV7E7rUMrtGvCergApybolVweNEXElS9yi+lSA3KBxW5aasDBDuLXggax9gVJv4KttdsWRcUiWeOsWZToSB0RGGJ+dxZ738elAvnJxDmBCGVaiYUmF6ATq0iad6F7aFO4LygLou/uahzWbjNcB7fHrFSq1rBVt2xUyvk1kfOdOt62Pp5yKtXw+3Xrcr7Cwf8KS9pwMT3P78Ik0MoXk6n/uC0a2v+Xwz9gyyqMvstLvhvJT7ZlwEH04g5Koh50DUYnn4oF0UO97OlR1gKnTiVBboGWc9TeM/2Xdd1J0zDCL7jb4MXzS1Oe8Ik1YED6wgwKMr8LaN0p4alZhhQraUyD3GsUbUnSIkMM5WwzosMQu7qpxq+LB7tJkcyx40PAgVRfUMrJY0xB9lwLda6CXekQLYvOx/Yr9WEss+MMzlgvYb+5Xy7mjkhZhlFQU3BINRotG1m0o5CWHlFKvrbwk6+hTRQUNvIsNDmol/fAOuNKTqOzrsJIsnD7tskPp60P+AMUatHbv4tY44RgN/gzCkbnNXWdmZQCgCETu/FPmW65TxMB/FoSEdqbz5Sxb3ZMs/FQIaL/3FeaB1+thY8md8nzHo5oe0tEOW4YLCRnkqX5+/uPCCIDsRjnZb531T3V5N/e0WZmaV9kMe4/lpjbzVeVmN9ME3VEG1XYyC7qQoCKX5jmq7FV4trXhdG3PU0q3MZs7oGesfGREi0+WPzslIoyE0Ig6hbb3MgROsmkCGfHyB8efl2yelzGH4JJE5HDNOX+2KZooLE4SBDa15TzXm4jGmJwB4BQvh4vVRrYbiatjnXci3XRZV7+DYZgI6Nw681XLeuyVJiRZCJYX+SPIGdQvWR+878a/E8CXSEDI82psvEKdPUcE9awcM2iLOblVk/gF+yxVeWO2I4GLs4T+/D/dqEcODYgxon9v5aoWsnkf7cWR3qdVFXfWYbcn7aLgFZkdbnehB5UwBd4m2uPe4miJPS2Ln49gkzm8LGSW2Fr6yF2iQRnGSYPPcKZpFrtkC6YdTxLLzItP56FpMOQRJ8QTayPPP097ywAXTG0uWLwPnqpQOmtKYJdQxMxt+qK8y7V7Xp4TRerfhfWyXGGP/IDta2oS8jAe4qH/Zw7gOK95hchddWemaKZsmjRytFnnD5iutS570YQI9VLZZ3+TEl0sVF9LN19onOafPUL3FVDHUzbX05sHk=",

"SKa":
"Dfv9HJoWfWwmZaLSzTkmgjStYDd/9ud0vYfVWa8fHczjX4wfPpPYQIxroX+WIIP/C0ij3CV6glltp9zp+elrcw==",

"SKb":
"65dS9X24jNvq3Gscnxre9fKpJEs+ksGjn7j4Mb/cfWuXuzgMy1bRTTZhNRbfmad/Izfd1YBoBu7u6hbIzaT6rQ==",

"Salt": "L07owL8dcqNnRDj05oEtGg==",

"SessionID": "wPaiF0Y+Feaz85V+px3Gq5J1puLqyg5c1qSOU7mKXeg="

}

Case without OTC
----------------

{

"AD": "WJ0Zli/KfaFz/rY5sHy0ThSCGfIkO4VoBr4AGpSQXYQ=",

"AdditionalData":
"2NFXIi2x1aXr8B8LDu2R4NorQDwOnII77MMrReUze2pkYcZlCN/3npPPTTe1v2D1EUSELLFYWCAk1y0Reopo0lZpcmdpbA==",

"Ciphertext":
"XbUNDlNhFIo0r+xlU1vctOhk5TulRRV6c9JGZhfSRNL6bUJmFzItq54icna5u7jQ4PulGYGhlGwBFXJom6/HzeVW9/zRRBE5awuk+cfhYh0NxSkB/nl+2+AAbha/l15cgeqGej6aL2UHW22WkDzsdsH7QhB1Z/vZIvkepsE4PMncdYWZxH8g+cQVWDKecS7e919ODvrI0JQj4m4QwNjCYtUhz1eRAvGFiof4qz04KQONctgp0Si4m959QbcQ+VQ6MhgJ7whpVkd/FmsY2rKtjW04/t6sYt4oRX+BW1SEyZfr6h32eJnl3nB6AEXBc0JQkNBp7j5uetIOs4LbZEyj8DRB0zzBuXrRCpw4RNUXIIBPTEflGyd4NXw0/d1JOG5hrALg63ZdiffwyiF0NdXcADSj0usBE+0o2kFchemtiU7HSo0YCCDgjovPt6Q+DGtPApPaaIr5bQRiy2gIBS08F2zq5oODgSgvUbIRCiz7fg4fH0oK3UKSc52gnnFyNwrdcBIf4Ptfmxm7ehptqO5F/47huUsAgGsf2rwbzCULNDzHZ0BLUaYqidWFPm0FPiJov2bRzEHoe3LWHsfMKPosB4fV4JKvRXjCUKQTsbqJ260k6S9scSl3bHLilE23zf2gB4IU3wUQndIiGFQ+JDFshiLfQB1PuPuEy6fXPGSHViLb+PDUpaKLIvAlKtNRnouCDm5Z6Q2EO6PnJkrZnEdbbJKxukeDpoqI6DsnRQbu93tKG/lpFGVM8UdpLF+VEFV8lBxjTFDDPTJJFJo+ShcSO+SQIhoRIBIqqKYqJp4ZRgPE8jb+/KPs4nTAswqz4ZDcM5hCHEgc9NbQDIP8Ppe93tqFT+Z+C6ao5XWL4gIo/JOmF1LUnEu4hnNYnWRatiIpln5RDWgn3uW15cSreOq7MyKGObVtQp2uSADQuQrsinVQiVxH3arnA9altXwKUFBIvfnLchkGLc+BfATibAzOTdWLLXtSYjtqiAwUvGq1gj2KMCXLZnoMRFx7q9j8OyqljmmdKzUqNelSFpGXoRVLgNuZa5062jgzBYS4TqPo2gh4ErIwtjtdoZCV4zbBTb/D7zHpJmpHCLX8iTqv3XFls13a5MB3OzJE9lwxHzqyESjMyCkHo9LnWTlQFEkBwOrBqvRU5mf1h9pAooyM6Q8pdB6qf79uSXa4HACD0RDxq6BxHj8aJq7mB3lPSNi69bY6/IZ/jB6l0dP6kCq+T68ulkrA3ekXO8dl4mnJPJwv6rjuUjREAXA/W2MYHTCm8J/1cucWbWoxbKU4TqUw6C6bPiZmJa38FLRZT0V34phrouEqYnDet2ipD9aes7hTBw8iRkSrBAeXdMYdq+Jeb55SvxyoZQBjl7jh6WUj8iPGDZE0",

"EKa":
"MC4CAQAwBQYDK2VwBCIEILsd4kQcLAOoRTpsVzJ8LchyR7XabfwGncSDO++a+k3d",

"ICa":
"MC4CAQAwBQYDK2VwBCIEIKTQZQbAkAPoJUI41tn4J5d/3r0Y7l7ShIheAGnSiJDt",

"ICb":
"MC4CAQAwBQYDK2VwBCIEIE01hYOMzFFophNeVgjIe2ZBhbMeaO4UA1yyiPeZkNkS",

"LTCb":
"MC4CAQAwBQYDK2VwBCIEIMFf8O+YM9m2QEJBfDHvODMaCWBT1qVsOGCcImltglCk",

"Plaintext":
"T9CP0XLwYDFXPyRjtpnkVDw3NpuDJPlzIPUjzoOW84GNwLMqRkGULRDVgmtumFkNwUtihPqygIB/qX9p/oa96aiL484+wznmm49eLZMRZP93eVpDPEGs555nntWVu4d34y8XF/6siHbti8+dJDUnEg4nWyWVWsIqJ2U9rYM+zd2c0z9vBFFCispjAKExsLWR82pc4V81OCnlpIpkvSAfFnpPAfFtFR3CBWC3LudzPrmDbWEWDJvJLH6+RO92gXwtUjFrCKHy6eFQPxG0zXdalqO1RsD95oiWF/f2csQyfxjKw5g/zA95bHY9QTQtEugdmKGWkY995lCaFoVNbHTWUH5ZRNrHLz6y7JkVezwnVZokvhNKL3haTtxTodryE+cHgzKnflbhYqLLO9SMz8BrvQrP0Cn7XerVUspnFY1H9Exgvm3wP9i0aVfS78TjVHLsb6DBtA9HGaFv5E6HZpyXuy1uhJVQG4BZx1NDE81t0w0HHszHVtOs3dWGpgfIEh/liN/6r01hGjQyxgSz4E6qf6P05oEIW8dzZa8VGfsgNT7lVvO1OMJpCiPPotcP9cOcQl2FOGO2PA+UPYq0E+1lbAE9MunEtDBiTffAlVXzdW7pre9qF40dcAJU9WMe8zY8RFtJh4IiFEZU3OVtzdzMfVQAs3gNw/KPd0dKz/P0T/FNEoemlhdLTSWJ2lJv+eDIlnHySyWgc27Hvm9mFrCLhv8DPCy0gujEjGMswxy9KdWzmfhdubDHYcKtiO7D4nQzY3B7ZBx8hqIoXdmtqAHIwHDvVNmv0AQhqzflkPJnOEW5CoYG/6s3YV9phNliUDxLgEuDI2b5ZSDwi2iIqb1rGnE/yvC/A2hee8Dg/09bVr31Holz/X2R0bAXBCBor31I4xHBPgUzKimn1yDDrzFqV4p5g2GHBf2nbiBltRoFchF6PXo4hJLM4h39DDez4m+r9q+8AUQGyGDTV/+l0riKU58BNT9rtdIVPW1hNhkqN9kIWT4NLKn9RQt+sOsMZbRU/YJ8ZDcFPO0lKZlrQbxvltUpTOxYePd0wUMnsNln7IKWEtxW+WJfE8eR6Lv0aZqiJ6LvocpVlHq0YRjdwf/ouiZTjaZ6qKemeHUQWN+qVn8zALx3+oPUTtc3L3bq9UZTJUUygj5pwEcOa6NOip0h2U35sbBEK9wHu8S/wAlMogN9S0q58kb9JFoS00K93tYArwi4M3PiCDqvs/agXJtEL0/G6wvmUJRjtieDwp30GFAmTWrE0rV3YMDXhchrvEYhXKWYFXJAq9ZG0UATxcaxzBdaNDd4CyMU3Kb6Rs3qaW0y9RYzV2PSRyaAM/WpT5NTtnKWYdaLq50Nt/XsohB2P4Q=",

"SKa":
"gvxX95gx28JZwiljjt1KuZXwK3e8vFoLjnB8l6SE7brRXTgMPhFsYuHZYihJ+j2WIoTEXs4liQRtxPm6Zypvmw==",

"SKb":
"kIGT4AlnWFUOkAureAdKS9wmU7HmtEkvGl7iH7KwK3XbaMsRzhP6UuvmT6OMmL3OmrV/8M6LUYQ4hHi64g37sA==",

"Salt": "LQZWWkvgzSQAnLpLg2Vzjw==",

"SessionID": "JrAdWOs0+eCWZFFZsObWTta63eBq3/lTpdwY1xy29OQ="

}
