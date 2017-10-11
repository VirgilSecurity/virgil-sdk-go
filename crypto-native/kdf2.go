package cryptonative

import (
	"encoding/binary"
	"hash"
)

//Kdf2 derives length crypto bytes from key and a hash function
func kdf2(key []byte, length int, h func() hash.Hash) []byte {
	kdfHash := h()
	outLen := kdfHash.Size()

	cThreshold := (length + outLen - 1) / outLen
	var counter uint32 = 1
	outOff := 0
	res := make([]byte, length)
	b := make([]byte, 4)
	for i := 0; i < cThreshold; i++ {
		kdfHash.Write(key)
		binary.BigEndian.PutUint32(b, counter)
		kdfHash.Write(b)
		counter++
		digest := kdfHash.Sum(nil)

		if length > outLen {
			copy(res[outOff:], digest[:])
			outOff += outLen
			length -= outLen
		} else {
			copy(res[outOff:], digest[:length])
		}
		kdfHash.Reset()
	}
	return res

}
