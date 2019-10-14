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
	"math"
	"reflect"
	"testing"
)

type tagAndLengthTest struct {
	in  []byte
	ok  bool
	out tagAndLength
}

var tagAndLengthData = []tagAndLengthTest{
	{[]byte{0x80, 0x01}, true, tagAndLength{2, 0, 1, false}},
	{[]byte{0xa0, 0x01}, true, tagAndLength{2, 0, 1, true}},
	{[]byte{0x02, 0x00}, true, tagAndLength{0, 2, 0, false}},
	{[]byte{0xfe, 0x00}, true, tagAndLength{3, 30, 0, true}},
	{[]byte{0x1f, 0x1f, 0x00}, true, tagAndLength{0, 31, 0, false}},
	{[]byte{0x1f, 0x81, 0x00, 0x00}, true, tagAndLength{0, 128, 0, false}},
	{[]byte{0x1f, 0x81, 0x80, 0x01, 0x00}, true, tagAndLength{0, 0x4001, 0, false}},
	{[]byte{0x00, 0x81, 0x80}, true, tagAndLength{0, 0, 128, false}},
	{[]byte{0x00, 0x82, 0x01, 0x00}, true, tagAndLength{0, 0, 256, false}},
	{[]byte{0x00, 0x83, 0x01, 0x00}, false, tagAndLength{}},
	{[]byte{0x1f, 0x85}, false, tagAndLength{}},
	{[]byte{0x30, 0x80}, false, tagAndLength{}},
	// Superfluous zeros in the length should be an error.
	{[]byte{0xa0, 0x82, 0x00, 0xff}, false, tagAndLength{}},
	// Lengths up to the maximum size of an int should work.
	{[]byte{0xa0, 0x84, 0x7f, 0xff, 0xff, 0xff}, true, tagAndLength{2, 0, 0x7fffffff, true}},
	// Lengths that would overflow an int should be rejected.
	{[]byte{0xa0, 0x84, 0x80, 0x00, 0x00, 0x00}, false, tagAndLength{}},
	// Long length form may not be used for lengths that fit in short form.
	{[]byte{0xa0, 0x81, 0x7f}, false, tagAndLength{}},
	// Tag numbers which would overflow int32 are rejected. (The value below is 2^31.)
	{[]byte{0x1f, 0x88, 0x80, 0x80, 0x80, 0x00, 0x00}, false, tagAndLength{}},
	// Tag numbers that fit in an int32 are valid. (The value below is 2^31 - 1.)
	{[]byte{0x1f, 0x87, 0xFF, 0xFF, 0xFF, 0x7F, 0x00}, true, tagAndLength{tag: math.MaxInt32}},
	// Long tag number form may not be used for tags that fit in short form.
	{[]byte{0x1f, 0x1e, 0x00}, false, tagAndLength{}},
}

func TestParseTagAndLength(t *testing.T) {
	for i, test := range tagAndLengthData {
		tagAndLength, _, err := parseTagAndLength(test.in, 0)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did pass? %v, expected: %v)", i, err == nil, test.ok)
		}
		if err == nil && !reflect.DeepEqual(test.out, tagAndLength) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, tagAndLength, test.out)
		}
	}
}
