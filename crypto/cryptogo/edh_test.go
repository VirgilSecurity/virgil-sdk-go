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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestX3DH(t *testing.T) {

	ICa, err := NewKeypair()
	assert.NoError(t, err)

	EKa, err := NewKeypair()
	assert.NoError(t, err)

	ICb, err := NewKeypair()
	assert.NoError(t, err)

	LTCb, err := NewKeypair()
	assert.NoError(t, err)

	OTCb, err := NewKeypair()
	assert.NoError(t, err)

	sk1, err := EDHInit(ICa.PrivateKey(), EKa.PrivateKey(), ICb.PublicKey(), LTCb.PublicKey(), OTCb.PublicKey())
	assert.NoError(t, err)

	sk2, err := EDHRespond(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), OTCb.PrivateKey())

	assert.NoError(t, err)
	assert.Equal(t, sk1, sk2)

	sk2, err = EDHRespond(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), nil)

	assert.NoError(t, err)
	assert.NotEqual(t, sk1, sk2)

	sk1, err = EDHInit(ICa.PrivateKey(), EKa.PrivateKey(), ICb.PublicKey(), LTCb.PublicKey(), nil)
	assert.NoError(t, err)
	assert.Equal(t, sk1, sk2)

}
