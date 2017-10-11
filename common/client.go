package common

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

type VirgilHttpClient struct {
	Client  *http.Client
	Address string
}

func (vc *VirgilHttpClient) Send(method string, url string, payload interface{}, respObj interface{}) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return errors.Wrap(err, "VirgilHttpClient.Send: marshal payload")
		}
	}
	req, err := http.NewRequest(method, vc.Address+url, bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "VirgilHttpClient.Send: new request")
	}
	client := vc.getHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "VirgilHttpClient.Send: send request")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return EntityNotFoundErr
	}
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "VirgilHttpClient.Send: read response body")
	}

	if resp.StatusCode == http.StatusOK {
		if respObj != nil {
			err = json.Unmarshal(respBody, respObj)
			if err != nil {
				return errors.Wrap(err, "VirgilHttpClient.Send: unmarshal response object")
			}
		}
		return nil
	}
	var virgilErr VirgilAPIError
	err = json.Unmarshal(respBody, &virgilErr)
	if err != nil {
		return errors.Wrap(err, "VirgilHttpClient.Send: unmarshal response object")
	}
	return virgilErr
}

func (vc *VirgilHttpClient) getHttpClient() *http.Client {
	if vc.Client != nil {
		return vc.Client
	}
	return http.DefaultClient
}
