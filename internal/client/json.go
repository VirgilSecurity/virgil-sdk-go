package client

import (
	"encoding/json"
)

type JSONCodec struct{}

func (JSONCodec) Marshal(obj interface{}) (body []byte, err error) {
	return json.Marshal(obj)
}

func (JSONCodec) Unmarshal(data []byte, obj interface{}) error {
	return json.Unmarshal(data, obj)
}

func (JSONCodec) Name() string {
	return "application/json"
}
