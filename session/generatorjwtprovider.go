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

import "github.com/VirgilSecurity/virgil-sdk-go/v6/errors"

type GeneratorJwtProviderOption func(p *GeneratorJwtProvider)

func SetGeneratorJwtProviderAddtionalData(additionalData map[string]interface{}) GeneratorJwtProviderOption {
	return func(p *GeneratorJwtProvider) {
		p.additionalData = additionalData
	}
}

func SetGeneratorJwtProviderDefaultIdentity(identity string) GeneratorJwtProviderOption {
	return func(p *GeneratorJwtProvider) {
		p.defaultIdentity = identity
	}
}

type GeneratorJwtProvider struct {
	jwtGenerator    JwtGenerator
	additionalData  map[string]interface{}
	defaultIdentity string
}

func NewGeneratorJwtProvider(generator JwtGenerator, options ...GeneratorJwtProviderOption) *GeneratorJwtProvider {
	p := &GeneratorJwtProvider{
		jwtGenerator:    generator,
		defaultIdentity: "default_identity",
	}

	for i := range options {
		options[i](p)
	}
	if err := generator.Validate(); err != nil {
		panic(err)
	}

	return p
}

func (g *GeneratorJwtProvider) GetToken(context *TokenContext) (AccessToken, error) {

	if context == nil {
		return nil, errors.NewSDKError(ErrContextIsMandatory, "action", "GeneratorJwtProvider.GetToken")
	}
	identity := context.Identity
	if identity == "" {
		identity = g.defaultIdentity
	}

	at, err := g.jwtGenerator.GenerateToken(identity, g.additionalData)
	if err != nil {
		return nil, errors.NewSDKError(err, "action", "GeneratorJwtProvider.GetToken")
	}
	return at, nil
}
