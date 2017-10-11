package cryptonative

import (
	"bytes"
	"crypto/rand"
	"testing"

	"gopkg.in/virgil.v6/crypto-native/gcm"
)

func TestStream(t *testing.T) {
	symmetricKey := make([]byte, 32) //256 bit AES key
	nonce := make([]byte, 12)        //96 bit AES GCM nonce

	rand.Reader.Read(symmetricKey)
	rand.Reader.Read(nonce)

	sc := StreamCipher

	plain := make([]byte, gcm.GcmStreamBufSize*2-20)
	rand.Reader.Read(plain)
	ad := make([]byte, 1)
	rand.Reader.Read(ad)
	for i := 0; i < 40; i++ {

		in := bytes.NewBuffer(plain)
		out := &bytes.Buffer{}
		err := sc.Encrypt(symmetricKey, nonce, ad, in, out)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		plainOut := &bytes.Buffer{}

		err = sc.Decrypt(symmetricKey, nonce, ad, out, plainOut)
		if err != nil {
			t.Fatalf("%d, %+v", i, err)
		}
		if bytes.Compare(plain, plainOut.Bytes()) != 0 {
			t.Fatal("plaintext and decrypted text do not match")
		}
		plain = append(plain, ad...)
	}
}

func TestChunk(t *testing.T) {
	symmetricKey := make([]byte, 32) //256 bit AES key
	nonce := make([]byte, 12)        //96 bit AES GCM nonce

	rand.Reader.Read(symmetricKey)
	rand.Reader.Read(nonce)

	sc := ChunkCipher
	plain := make([]byte, gcm.GcmStreamBufSize*3-20)
	rand.Reader.Read(plain)
	ad := make([]byte, 1)
	rand.Reader.Read(ad)
	for i := 0; i < 40; i++ {
		in := bytes.NewBuffer(plain)
		out := &bytes.Buffer{}
		err := sc.Encrypt(symmetricKey, nonce, ad, DefaultChunkSize, in, out)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		plainOut := &bytes.Buffer{}

		err = sc.Decrypt(symmetricKey, nonce, ad, DefaultChunkSize, out, plainOut)
		if err != nil {
			t.Fatalf("%d, %+v", i, err)
		}
		if bytes.Compare(plain, plainOut.Bytes()) != 0 {
			t.Fatal("plaintext and decrypted text do not match")
		}
		plain = append(plain, ad...)
	}
}
