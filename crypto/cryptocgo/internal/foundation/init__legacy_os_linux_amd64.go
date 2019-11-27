// +build legacy_os

package foundation

// #cgo CFLAGS: -I${SRCDIR}/../pkg/linux_amd64__legacy_os/include/
// #cgo LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64__legacy_os/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
import "C"
