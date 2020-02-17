package client

import (
	"encoding/json"
)

type JSONCodec struct{}

func (c *JSONCodec) Marshal(obj interface{}) (body []byte, err error) {
	return json.Marshal(obj)
}

func (c *JSONCodec) Unmarshal(data []byte, obj interface{}) error {
	return json.Unmarshal(data, obj)
}

func (c *JSONCodec) Name() string {
	return "application/json"
}
