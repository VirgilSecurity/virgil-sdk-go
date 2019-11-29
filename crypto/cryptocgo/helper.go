package cryptocgo

import (
	"encoding/base64"
	"encoding/pem"
)

type deleter interface {
	Delete()
}

func delete(lst ...deleter) {
	for _, i := range lst {
		if i != nil {
			i.Delete()
		}
	}
}

func unwrapKey(key []byte) []byte {

	block, _ := pem.Decode(key)
	if block != nil {
		return block.Bytes
	} else {
		buf := make([]byte, base64.StdEncoding.DecodedLen(len(key)))

		read, err := base64.StdEncoding.Decode(buf, key)

		if err == nil {
			return buf[:read]
		}

		return key //already DER
	}
}
