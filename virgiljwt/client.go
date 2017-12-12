package virgiljwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/virgil.v6/crypto-api"
)

var DefaultTTL uint = 15

func Make(crypto cryptoapi.Crypto, sk cryptoapi.PrivateKey, accID string) JWTClient {
	return JWTClient{
		crypto:    crypto,
		secretKey: sk,
		accID:     accID,
	}
}

type JWTClient struct {
	crypto    cryptoapi.Crypto
	secretKey cryptoapi.PrivateKey
	accID     string
}

type JWTParam struct {
	AppIDs   []string
	TTL      uint      // count in minutes
	IssuedAt time.Time //UTC date
}

func (c JWTClient) Generate(p JWTParam) (string, error) {
	if p.IssuedAt.Before(time.Now()) {
		p.IssuedAt = time.Now()
	}
	if p.TTL == 0 {
		p.TTL = DefaultTTL
	}

	token := jwt.NewWithClaims(makeVirgilSigningMethod(), jwt.MapClaims{
		"accid":  c.accID,
		"appids": p.AppIDs,
		"ver":    "1.0",
		"iat":    p.IssuedAt.UTC().Unix(),
		"exp":    p.IssuedAt.Add(time.Duration(p.TTL) * time.Minute).UTC().Unix(),
	})
	return token.SignedString(secretKey{Crypto: c.crypto, Key: c.secretKey})
}
