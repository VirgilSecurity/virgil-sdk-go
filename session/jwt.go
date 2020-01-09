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
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/errors"
)

type Jwt struct {
	BodyContent   JwtBodyContent
	HeaderContent JwtHeaderContent
	Signature     []byte

	// signedToken and unsignedToken are updated when invoke Jwt.Sign
	signedToken   string
	unsignedToken []byte
}

// NewJwt return new instance of Jwt
// Note: JwtBodyContent is huge params but it's never used other place
// nolint: gocritic
func NewJwt(header JwtHeaderContent, body JwtBodyContent) *Jwt {
	jwt := &Jwt{
		HeaderContent: header,
		BodyContent:   body,
	}
	return jwt
}

func JwtFromString(token string) (*Jwt, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.NewSDKError(ErrJWTParseFailed, "action", "JwtFromString")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.NewSDKError(err, "action", "JwtFromString", "part", "header")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.NewSDKError(err, "action", "JwtFromString", "part", "body")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.NewSDKError(err, "action", "JwtFromString", "part", "signature")
	}

	var headerContent JwtHeaderContent
	if err := json.Unmarshal(header, &headerContent); err != nil {
		return nil, errors.NewSDKError(err, "action", "JwtFromString", "part", "header")
	}

	var bodyContent JwtBodyContent
	if err := json.Unmarshal(body, &bodyContent); err != nil {
		return nil, errors.NewSDKError(err, "action", "JwtFromString", "part", "body")
	}

	if !strings.Contains(bodyContent.Issuer, IssuerPrefix) || !strings.Contains(bodyContent.Subject, IdentityPrefix) {
		return nil, errors.NewSDKError(ErrJWTIncorrect, "action", "JwtFromString")
	}

	bodyContent.AppID = strings.TrimPrefix(bodyContent.Issuer, IssuerPrefix)
	bodyContent.Identity = strings.TrimPrefix(bodyContent.Subject, IdentityPrefix)

	return &Jwt{
		BodyContent:   bodyContent,
		HeaderContent: headerContent,
		Signature:     signature,
		signedToken:   token,
		unsignedToken: []byte(parts[0] + "." + parts[1]),
	}, nil
}

func (j *Jwt) String() string {
	return j.signedToken
}

func (j *Jwt) Identity() (string, error) {
	return j.BodyContent.Identity, nil
}

func (j *Jwt) IsExpired() error {
	return j.IsExpiredDelta(0)
}

//IsExpiredDelta returns error if token expires delta time before it's expiry date
func (j *Jwt) IsExpiredDelta(delta time.Duration) error {
	exp := time.Unix(j.BodyContent.ExpiresAt, 0).Add(-delta)
	now := time.Now()

	if exp.Before(now) {
		return ErrJWTExpired
	}
	return nil
}

func (j *Jwt) headerBase64() (string, error) {
	headerBytes, err := json.Marshal(j.HeaderContent)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(headerBytes), nil
}

func (j *Jwt) bodyBase64() (string, error) {
	bodyBytes, err := json.Marshal(j.BodyContent)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bodyBytes), nil
}

func (j *Jwt) signatureBase64() string {
	return base64.RawURLEncoding.EncodeToString(j.Signature)
}

func (j *Jwt) Sign(c AccessTokenSigner, key crypto.PrivateKey) error {
	h, err := j.headerBase64()
	if err != nil {
		return err
	}
	b, err := j.bodyBase64()
	if err != nil {
		return err
	}
	unsigned := h + "." + b
	j.unsignedToken = []byte(unsigned)
	sign, err := c.GenerateTokenSignature(j.unsignedToken, key)
	if err != nil {
		return err
	}
	j.Signature = sign
	j.signedToken = unsigned + "." + j.signatureBase64()
	return nil
}

func (j *Jwt) Verify(c AccessTokenSigner, key crypto.PublicKey) error {
	return c.VerifyTokenSignature(j.unsignedToken, j.Signature, key)
}

// jwt body prefixes
const (
	IdentityPrefix = "identity-"
	IssuerPrefix   = "virgil-"
)

type JwtBodyContent struct {
	AppID          string                 `json:"-"`
	Identity       string                 `json:"-"`
	Issuer         string                 `json:"iss"`
	Subject        string                 `json:"sub"`
	IssuedAt       int64                  `json:"iat"`
	ExpiresAt      int64                  `json:"exp"`
	AdditionalData map[string]interface{} `json:"ada,omitempty"`
}

// jwt header constant
const (
	VirgilContentType = "virgil-jwt;v=1"
	JwtType           = "JWT"
)

type JwtHeaderContent struct {
	Algorithm   string `json:"alg"`
	Type        string `json:"typ"`
	ContentType string `json:"cty"`
	AppKeyID    string `json:"kid"`
}
