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

package errors

import (
	"strings"
)

func NewSDKError(err error, params ...string) error {
	if err == nil {
		return nil
	}

	m := make(map[string]string)
	for i := 0; i < len(params); i++ {
		var val = "val_is_missed"
		if i+1 < len(params) {
			val = params[i+1]
		}
		m[params[i]] = val
		i++
	}
	return &SDKError{
		Params:   m,
		InnerErr: err,
	}
}

type SDKError struct {
	Params   map[string]string
	InnerErr error
}

//nolint:gosec,stylecheck
func (e *SDKError) Error() string {
	var b strings.Builder
	b.WriteString("sdk error { ")
	for k, v := range e.Params {
		b.WriteString(k + ": " + v)
	}
	b.WriteString("}: ")
	b.WriteString(e.InnerErr.Error())
	return b.String()
}

func (e *SDKError) Unwrap() error {
	return e.InnerErr
}

func (e *SDKError) Cause() error {
	return e.InnerErr
}
