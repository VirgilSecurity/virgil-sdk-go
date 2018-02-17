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

package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v5/cryptoimpl"
)

func TestJwtVerifier_VerifyToken(t *testing.T) {

	pub, err := cryptoimpl.NewVirgilCrypto().ImportPublicKey([]byte("MCowBQYDK2VwAyEAiWNcK5Ipp27VXciJNsG1ZxESEq5xWniendU/8yo5318="))
	assert.NoError(t, err)

	verifier := NewJwtVerifier(pub, "a2ae26f9ed0453cb49e83e8ed045e801e75c77efb162ca152f62f699cf95ff8b58848da3968a05fa2949e12c225ef6fa0e999b83e6bc15aa8e3a530e44837d7c", cryptoimpl.NewVirgilAccessTokenSigner())

	jwt, err := JwtFromString("eyJhbGciOiJWRURTNTEyIiwiY3R5IjoidmlyZ2lsLWp3dDt2PTEiLCJraWQiOiJhMmFlMjZmOWVkMDQ1M2NiNDllODNlOGVkMDQ1ZTgwMWU3NWM3N2VmYjE2MmNhMTUyZjYyZjY5OWNmOTVmZjhiNTg4NDhkYTM5NjhhMDVmYTI5NDllMTJjMjI1ZWY2ZmEwZTk5OWI4M2U2YmMxNWFhOGUzYTUzMGU0NDgzN2Q3YyIsInR5cCI6IkpXVCJ9.eyJhZGEiOnsidXNlcm5hbWUiOiJzb21lX3VzZXJuYW1lIn0sImV4cCI6MTUxODQyNjQzOSwiaWF0IjoxNTE4NDI1ODM5LCJpc3MiOiJ2aXJnaWwtZDI5YWQxZTkwODFmMzQ5Njg3M2QxM2NmZDg2YzViZGYwMTk2MDRhODM5MDkxZmIyZmMyMzUwZDY2N2ViMDI0NSIsInN1YiI6ImlkZW50aXR5LXNvbWVfaWRlbnRpdHkifQ.MFEwDQYJYIZIAWUDBAIDBQAEQFUGKh0Y07eRHWv_ThNJsQ-0mxfVAx86BYdcnr1LBSK9MOxzPZMhdu0kg3RcALnHZWPPIlKHZ8g_AtHXIynM5gg")
	assert.NoError(t, err)
	assert.NoError(t, verifier.VerifyToken(jwt))
}
