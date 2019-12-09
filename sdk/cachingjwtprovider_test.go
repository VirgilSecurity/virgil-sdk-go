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
 *
 */

package sdk

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo"
)

func TestCachingJwtProvider(t *testing.T) {
	crypto := cryptocgo.NewVirgilCrypto()

	key, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	genCount := 0

	jwtGenerator := JwtGenerator{
		ApiKey:                 key,
		ApiPublicKeyIdentifier: hex.EncodeToString(key.Identifier()),
		TTL:                    6 * time.Second,
		AccessTokenSigner:      cryptocgo.NewVirgilAccessTokenSigner(),
		AppID:                  "app_id",
	}

	prov := NewCachingJwtProvider(func(context *TokenContext) (*Jwt, error) {
		genCount++
		return jwtGenerator.GenerateToken(context.Identity, nil)
	})

	routines := 100

	wg := &sync.WaitGroup{}
	wg.Add(routines)

	start := time.Now()

	for i := 0; i < routines; i++ {
		go func() {
			defer wg.Done()

			for time.Since(start) < (time.Second * 5) {
				token, err := prov.GetToken(&TokenContext{Identity: "Alice"})
				assert.NotNil(t, token)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 6, genCount)
}
