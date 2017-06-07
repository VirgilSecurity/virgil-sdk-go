package virgil

import (
	"encoding/base64"
	"encoding/hex"
)

type Buffer []byte

func BufferFromString(str string) Buffer {
	return Buffer(str)
}

func BufferFromHEXString(str string) (Buffer, error) {
	return hex.DecodeString(str)
}

func BufferFromBase64String(str string) (Buffer, error) {
	res, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func BufferFromBytes(data []byte) Buffer {
	return Buffer(data)
}

func (b Buffer) ToString() string {
	return string(b)
}

func (b Buffer) ToHEXString() string {
	return hex.EncodeToString(b)
}

func (b Buffer) ToBase64String() string {
	return base64.StdEncoding.EncodeToString(b)
}
