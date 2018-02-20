// +build integration

package sdk

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"crypto/rand"
	"encoding/hex"

	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v5/common"
	"gopkg.in/virgil.v5/errors"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

func initCardManager() (*CardManager, error) {
	apiUrl := os.Getenv("TEST_ADDRESS")
	accID := os.Getenv("TEST_ACC_ID")
	if accID == "" {
		return nil, errors.New("TEST_ACC_ID is required")
	}
	apiKeySource := os.Getenv("TEST_API_KEY")
	if apiKeySource == "" {
		return nil, errors.New("TEST_API_KEY is required")
	}
	apiKey, err := crypto.ImportPrivateKey([]byte(apiKeySource), "")
	if err != nil {
		return nil, errors.Wrap(err, "Cannot import API private key: ")
	}

	appID := os.Getenv("TEST_APP_ID")
	if appID == "" {
		return nil, errors.New("TEST_APP_ID is required")
	}

	verifier, err := NewVirgilCardVerifier(cardCrypto, true, true)

	if err != nil {
		panic(err)
	}

	serviceKey := os.Getenv("TEST_SERVICE_KEY")
	if serviceKey != "" {
		err = verifier.ReplaceVirgilPublicKey(serviceKey)
		if err != nil {
			panic(err)
		}
	}

	generator := NewJwtGenerator(apiKey, accID, virgil_crypto_go.NewVirgilAccessTokenSigner(), appID, time.Minute*1)
	cardsClient := NewCardsClient(apiUrl)
	cardsClient.HttpClient = &DebugClient{}
	params := &CardManagerParams{
		Crypto:              cardCrypto,
		ApiUrl:              apiUrl,
		CardVerifier:        verifier,
		ModelSigner:         NewModelSigner(cardCrypto),
		AccessTokenProvider: NewGeneratorJwtProvider(generator, nil, ""),
		CardClient:          cardsClient,
	}
	return NewCardManager(params)
}

func TestCardManager_Integration_Publish_Get_Search(t *testing.T) {

	manager, err := initCardManager()
	assert.NoError(t, err)

	card, err := PublishCard(t, manager, "Alice-"+randomString(), "")
	assert.NoError(t, err)
	card, err = manager.GetCard(card.Identifier)
	assert.NoError(t, err)
	assert.NotNil(t, card)

	cards, err := manager.SearchCards(card.Identity)

	assert.NoError(t, err)
	assert.True(t, len(cards) > 0)

	cards, err = manager.SearchCards(randomString())
	assert.True(t, len(cards) == 0)
	assert.NoError(t, err)
}

func TestCardManager_Integration_Publish_Replace(t *testing.T) {

	manager, err := initCardManager()
	assert.NoError(t, err)

	oldCard, err := PublishCard(t, manager, "Alice-"+randomString(), "")
	assert.NoError(t, err)

	newCard, err := PublishCard(t, manager, oldCard.Identity, oldCard.Identifier)
	assert.NoError(t, err)
	assert.NotNil(t, newCard)

	oldCard, err = manager.GetCard(oldCard.Identifier)
	assert.NoError(t, err)
	assert.NotNil(t, oldCard)
	assert.True(t, oldCard.IsOutdated)

}

func TestCardManager_Integration_Publish_Replace_Link(t *testing.T) {

	manager, err := initCardManager()
	assert.NoError(t, err)

	identity := "Alice-" + randomString()

	for i := 0; i < 3; i++ { //3 branches of 3 cards each
		prev := ""
		for j := 0; j < 3; j++ {
			card, err := PublishCard(t, manager, identity, prev)
			assert.NoError(t, err)
			prev = card.Identifier
		}
	}

	cards, err := manager.SearchCards(identity)
	assert.NoError(t, err)

	assert.True(t, len(cards) == 3)

	for _, card := range cards {
		current := card
		for i := 0; i < 2; i++ {
			assert.True(t, current.PreviousCard != nil)
			assert.True(t, current.PreviousCard.Identifier == current.PreviousCardId)
			current = current.PreviousCard
		}
	}

}

func PublishCard(t *testing.T, manager *CardManager, identity string, previousCardId string) (*Card, error) {
	kp, err := crypto.GenerateKeypair()
	assert.NoError(t, err)

	cardParams := &CardParams{
		PublicKey:      kp.PublicKey(),
		PrivateKey:     kp.PrivateKey(),
		Identity:       identity,
		PreviousCardId: previousCardId,
		ExtraFields:    map[string]string{"key": "value"},
	}

	card, err := manager.PublishCard(cardParams)
	assert.NoError(t, err)
	assert.Equal(t, card.Identity, cardParams.Identity)
	return card, err
}

type DebugClient struct {
	Client common.HttpClient
}

func (c *DebugClient) Do(req *http.Request) (*http.Response, error) {
	var (
		body []byte
		err  error
	)
	fmt.Println("Request:", req.Method, req.URL.String())

	if len(req.Header) > 0 {
		fmt.Println("Header:")
		for key := range req.Header {
			fmt.Println("\t", key, ":", req.Header.Get(key))
		}
		fmt.Println("")
	}
	if req.Body != nil {
		body, err = ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("Cannot read body request: %v", err)
		}
		fmt.Println("Body:", string(body))
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	resp, err := c.getClient().Do(req)
	if err != nil {
		return resp, err
	}
	fmt.Println("Response:", resp.StatusCode)
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Cannot read body request: %v", err)
	}
	fmt.Println("Body:", string(body))
	resp.Body = ioutil.NopCloser(bytes.NewReader(body))

	fmt.Println("")
	return resp, nil
}

func (c *DebugClient) getClient() common.HttpClient {
	if c.Client == nil {
		return http.DefaultClient
	}
	return c.Client
}

func randomString() string {
	buf := make([]byte, 10)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}
