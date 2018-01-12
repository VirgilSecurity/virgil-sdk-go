package virgiljwt

import (
	"testing"

	"encoding/hex"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v6/crypto-native"
)

func TestVirgilSigner_Sign(t *testing.T) {

	c := &cryptonative.VirgilCrypto{}

	kp, err := c.GenerateKeypair()

	assert.NoError(t, err)

	keyId := hex.EncodeToString(kp.PublicKey().ReceiverID())

	identity := "alice"
	appId := "987654321011"

	jwtMaker := Make(c, kp.PrivateKey(), keyId)
	token, err := jwtMaker.Generate(JWTParam{AppID: appId, Identity: identity})

	assert.NoError(t, err)

	_, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

		assert.Equal(t, token.Header["alg"], VirgilSigningAlgorithm)
		assert.Equal(t, token.Header["cty"], "virgil-jwt;v=1")
		assert.Equal(t, token.Header["kid"], keyId)
		assert.Equal(t, token.Header["typ"], "JWT")

		claims := token.Claims.(jwt.MapClaims)

		assert.NoError(t, claims.Valid())
		assert.True(t, claims.VerifyIssuer("virgil-"+appId, true))
		assert.Equal(t, claims["sub"], "identity-"+identity)

		return publicKey{Crypto: c, Key: kp.PublicKey()}, nil
	})
	assert.NoError(t, err)
}
