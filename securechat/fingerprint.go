package securechat

import (
	"crypto/sha512"
	"fmt"
	"sort"

	"github.com/pkg/errors"
)

const iterations = 4096

//NumberFingerprint generates a 60-digit string representation of 384 bit hash of supplied strings
func NumberFingerprint(cardIds []string) (string, error) {
	//fmt.Println(cardIds)
	if len(cardIds) == 0 {
		return "", errors.New("no cards provided")
	}

	sortedIds := make([]string, 0, len(cardIds))
	for _, c := range cardIds {
		if c == "" {
			return "", errors.New("one of the supplied cards is nil")
		}
		sortedIds = append(sortedIds, c)
	}

	sort.Slice(sortedIds, func(i, j int) bool {
		return sortedIds[i] < sortedIds[j]
	})

	var idsSlice []byte
	for _, id := range sortedIds {
		idsSlice = append(idsSlice, []byte(id)...)
	}

	h := sha512.New384()
	var hash []byte
	for i := 0; i < iterations; i++ {
		h.Write(idsSlice)
		h.Write(hash)
		hash = h.Sum(hash[:0])
		h.Reset()
	}

	return HashToStr(hash), nil
}

//makes 60 digit number from 384 bit hash
func HashToStr(hash []byte) (res string) {
	if len(hash) != 48 {
		panic("hash len is not 48")
	}
	for i := 0; i < 48; i += 4 {
		t := uint32(hash[i+0]) << 0
		t += uint32(hash[i+1]) << 8
		t += uint32(hash[i+2]) << 16
		t += uint32(hash[i+3]) << 24
		t = t % uint32(100000)
		res += fmt.Sprintf("%05d ", t)
	}

	return res[:len(res)-1]
}
