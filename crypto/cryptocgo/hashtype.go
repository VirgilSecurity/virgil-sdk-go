package cryptocgo

import (
	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo/internal/foundation"
)

type HashType int

const (
	Default HashType = iota
	Sha224
	Sha256
	Sha384
	Sha512
)

var hashMap = map[HashType]func() foundation.Hash{
	Default: func() foundation.Hash {
		return foundation.NewSha512()
	},
	Sha224: func() foundation.Hash {
		return foundation.NewSha224()
	},
	Sha256: func() foundation.Hash {
		return foundation.NewSha256()
	},
	Sha384: func() foundation.Hash {
		return foundation.NewSha384()
	},
	Sha512: func() foundation.Hash {
		return foundation.NewSha512()
	},
}
