package foundation

// #cgo CFLAGS: -I${SRCDIR}/../pkg/darwin_amd64/include/
// #cgo LDFLAGS: -L${SRCDIR}/../pkg/darwin_amd64/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lround5 -lfalcon -lkeccak
import "C"