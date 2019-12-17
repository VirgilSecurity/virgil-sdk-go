// +build !legacy_os

package foundation

// #cgo CFLAGS: -I${SRCDIR}/../pkg/linux_amd64/include/
// #cgo LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64/lib  -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lkeccak -pthread
import "C"