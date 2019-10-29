/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 *   (3) Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package cryptogo

import (
	"bytes"
	"io"
	"testing"
)

type badReader struct {
	buf io.Reader
}

func (r *badReader) Read(p []byte) (n int, err error) {
	n, err = r.buf.Read(p[:len(p)-1])
	if err != nil {
		return n, err // not our error
	}
	return n, CryptoError("bad reader read one byte less")
}

func TestSignatures(t *testing.T) {
	//make random data
	data := make([]byte, 257)
	readRandom(t, data)

	_, err := Signer.Sign(data, &ed25519PrivateKey{})
	if err == nil {
		t.Fatal("must fail with empty keypair")
	}

	keypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signature, err := Signer.Sign(data, keypair.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	//bad key

	err = Verifier.Verify(data, nil, signature)
	if err == nil {
		t.Fatal("must fail with nil key")
	}

	err = Verifier.Verify(data, &ed25519PublicKey{}, signature)
	if err == nil {
		t.Fatal("must fail with bad key")
	}

	err = Verifier.Verify(data, keypair.PublicKey(), data)
	if err == nil {
		t.Fatal("must fail with bad signature")
	}

	badSignature, err := makeSignature(make([]byte, 1), 32)
	if err != nil {
		t.Fatal(err)
	}

	err = Verifier.Verify(data, keypair.PublicKey(), badSignature)
	if err == nil {
		t.Fatal("must fail with bad signature size")
	}

	err = Verifier.Verify(data, keypair.PublicKey(), signature)
	if err != nil {
		t.Fatal(err)
	}

	//corrupt key
	keypair.PublicKey().contents()[0] = ^keypair.PublicKey().contents()[0]
	keypair.PublicKey().contents()[1] = ^keypair.PublicKey().contents()[1]

	err = Verifier.Verify(data, keypair.PublicKey(), signature)
	if err == nil {
		t.Fatal("Signature verification succeeded but must fail")
	}
}

func TestStreamSignatures(t *testing.T) {
	//make random data
	data := make([]byte, 255)
	readRandom(t, data)

	keypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}

	badbuf := &badReader{buf: bytes.NewBuffer(data)}
	_, err = Signer.SignStream(badbuf, keypair.PrivateKey())
	if err == nil {
		t.Fatal("read must fail")
	}

	buf := bytes.NewBuffer(data)
	signature, err := Signer.SignStream(buf, keypair.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	buf = bytes.NewBuffer(data)
	err = Verifier.VerifyStream(buf, keypair.PublicKey(), signature)
	if err != nil {
		t.Fatal(err)
	}

	//corrupt key
	keypair.PublicKey().contents()[0] = ^keypair.PublicKey().contents()[0]
	keypair.PublicKey().contents()[1] = ^keypair.PublicKey().contents()[1]
	buf = bytes.NewBuffer(data)
	err = Verifier.VerifyStream(buf, keypair.PublicKey(), signature)
	if err == nil {
		t.Fatal("Signature verification succeeded but must fail")
	}

	badbuf = &badReader{buf: bytes.NewBuffer(data)}
	err = Verifier.VerifyStream(badbuf, keypair.PublicKey(), signature)
	if err == nil {
		t.Fatal("read must fail")
	}

}

func BenchmarkEd25519Signer_Sign(b *testing.B) {
	keypair, err := NewKeypair()
	if err != nil {
		b.Fatal(err)
	}

	sk := keypair.PrivateKey()

	data := make([]byte, 300)

	for i := 0; i < b.N; i++ {
		_, err = Signer.Sign(data, sk)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519Verifier_Verify(b *testing.B) {
	keypair, err := NewKeypair()
	if err != nil {
		b.Fatal(err)
	}

	pk := keypair.PublicKey()

	data := make([]byte, 300)

	sign, err := Signer.Sign(data, keypair.PrivateKey())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := Verifier.Verify(data, pk, sign)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
