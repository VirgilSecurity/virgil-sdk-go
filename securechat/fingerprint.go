package securechat

import (
	"crypto/sha512"
	"fmt"
	"sort"

	"github.com/pkg/errors"
)

const iterations = 4096

//NumberFingerprint generates a string representation of
func NumberFingerprint(cardIds []string) (string, error) {

	if len(cardIds) == 0 {
		return "", errors.New("no cards provided")
	}

	tmp := make([]string, 0, len(cardIds))
	for _, c := range cardIds {
		if c == "" {
			return "", errors.New("one of the supplied cards is nil")
		}
		tmp = append(tmp, c)
	}

	sort.Slice(tmp, func(i, j int) bool {
		return tmp[i] < tmp[j]
	})

	h := sha512.New384()
	for i := 0; i < iterations; i++ {
		for j := 0; j < len(tmp); j++ {
			h.Write([]byte(tmp[j]))
		}
	}
	hash := h.Sum(nil)[:36] //we need only 32 bytes (256 bits)

	return HashToStr(hash), nil
}

//makes 60 digit number from 288 bit hash
func HashToStr(hash []byte) (res string) {
	if len(hash) != 36 {
		panic("hash len is not 36")
	}
	for i := 0; i < 36; i += 3 {
		t := uint32(hash[i])
		t += uint32(hash[i+1]) << 8
		t += uint32(hash[i+2]) << 16
		t = t % uint32(100000)
		res += fmt.Sprintf("%05d ", t)
	}

	return res[:len(res)-1]
}
