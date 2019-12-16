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

package session

import (
	"sync"
	"time"

	"github.com/VirgilSecurity/virgil-sdk-go/errors"
)

type CachingJwtProvider struct {
	RenewTokenCallback func(context *TokenContext) (*Jwt, error)
	Jwt                *Jwt
	lock               sync.RWMutex
}

func NewCachingJwtProvider(renewTokenCallback func(context *TokenContext) (*Jwt, error)) *CachingJwtProvider {
	if renewTokenCallback == nil {
		panic("callback is mandatory")
	}
	return &CachingJwtProvider{
		RenewTokenCallback: renewTokenCallback,
	}
}

func NewCachingStringJwtProvider(renewTokenCallback func(context *TokenContext) (string, error)) *CachingJwtProvider {
	if renewTokenCallback == nil {
		panic("callback is mandatory")
	}
	return NewCachingJwtProvider(func(context *TokenContext) (*Jwt, error) {
		token, err := renewTokenCallback(context)
		if err != nil {
			return nil, err
		}
		return JwtFromString(token)
	})
}

func (c *CachingJwtProvider) GetToken(context *TokenContext) (AccessToken, error) {
	if context == nil {
		return nil, errors.NewSDKError(ErrContextIsMandatory, "action", "CachingJwtProvider.GetToken")
	}

	// TODO: refactor
	c.lock.RLock()
	if c.Jwt != nil && c.Jwt.IsExpiredDelta(5*time.Second) == nil {
		c.lock.RUnlock()
		return c.Jwt, nil
	}
	c.lock.RUnlock()

	c.lock.Lock()
	defer c.lock.Unlock()
	if c.Jwt == nil || c.Jwt.IsExpiredDelta(5*time.Second) != nil {
		token, err := c.RenewTokenCallback(context)
		if err != nil {
			return nil, errors.NewSDKError(err, "action", "CachingJwtProvider.GetToken")
		}
		c.Jwt = token
	}
	return c.Jwt, nil
}