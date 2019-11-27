package foundation

// #cgo CFLAGS: -I${SRCDIR}/../pkg/windows_amd64/include/
// #cgo LDFLAGS: -L${SRCDIR}/../pkg/windows_amd64/lib  -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
import "C"
