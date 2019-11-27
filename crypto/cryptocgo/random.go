package cryptocgo

import (
	"fmt"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo/internal/foundation"
)

var random foundation.Random

func init() {
	rnd := foundation.NewCtrDrbg()

	if err := rnd.SetupDefaults(); err != nil {
		panic(fmt.Errorf("virgil crypto cannot initialize random generator: %v", err))
	}
	random = rnd
}
