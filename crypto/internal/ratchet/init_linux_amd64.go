// +build !legacy_os

package ratchet

// #cgo CFLAGS: -I${SRCDIR}/../pkg/linux_amd64/include/
// #cgo LDFLAGS: -L${SRCDIR}/../pkg/linux_amd64/lib/ -lvsc_ratchet -lvsc_ratchet_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
import "C"
