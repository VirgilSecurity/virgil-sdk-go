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

	"encoding/base64"

	"github.com/stretchr/testify/assert"
)

//STC-1
func TestRawSignedModel_ImportExport1(t *testing.T) {

	model1, err := GenerateRawSignedModelFromString("eyJjb250ZW50X3NuYXBzaG90IjoiZXlKamNtVmhkR1ZrWDJGMElqb3hOVEUxTmpnMk1qUTFMQ0pwWkdWdWRHbDBlU0k2SW5SbGMzUWlMQ0p3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVRaa09XSlJVVVoxUlc1Vk9IWlRiWGc1WmtSdk1GZDRaV00wTWtwa1RtYzBWbEkwUms5eU5DOUNWV3M5SWl3aWRtVnljMmx2YmlJNklqVXVNQ0o5Iiwic2lnbmF0dXJlcyI6W119")

	assert.NoError(t, err)

	model2, err := GenerateRawSignedModelFromJson(`{"content_snapshot":"eyJjcmVhdGVkX2F0IjoxNTE1Njg2MjQ1LCJpZGVudGl0eSI6InRlc3QiLCJwdWJsaWNfa2V5IjoiTUNvd0JRWURLMlZ3QXlFQTZkOWJRUUZ1RW5VOHZTbXg5ZkRvMFd4ZWM0MkpkTmc0VlI0Rk9yNC9CVWs9IiwidmVyc2lvbiI6IjUuMCJ9","signatures":[]}`)

	assert.NoError(t, err)
	assert.EqualValues(t, model1, model2)
	assert.True(t, len(model1.Signatures) == 0)

	var content1 *RawCardContent
	err = ParseSnapshot(model1.ContentSnapshot, &content1)
	assert.NoError(t, err)

	var content2 *RawCardContent
	err = ParseSnapshot(model1.ContentSnapshot, &content2)
	assert.NoError(t, err)

	assert.EqualValues(t, content1, content2)

	assert.Equal(t, content1.Identity, "test")
	assert.Equal(t, content1.Version, CardVersion)
	assert.Equal(t, content1.CreatedAt, int64(1515686245))
	pub, err := base64.StdEncoding.DecodeString("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=")
	assert.NoError(t, err)
	assert.Equal(t, content1.PublicKey, pub)
	assert.Equal(t, content1.PreviousCardId, "")

}

//STC-2
func TestRawSignedModel_ImportExport2(t *testing.T) {

	model1, err := GenerateRawSignedModelFromString("eyJjb250ZW50X3NuYXBzaG90IjoiZXlKamNtVmhkR1ZrWDJGMElqb3hOVEUxTmpnMk1qUTFMQ0pwWkdWdWRHbDBlU0k2SW5SbGMzUWlMQ0p3Y21WMmFXOTFjMTlqWVhKa1gybGtJam9pWVRZMk5qTXhPREEzTVRJM05HRmtZamN6T0dGbU0yWTJOMkk0WXpkbFl6STVaRGsxTkdSbE1tTmhZbVprTnpGaE9UUXlaVFpsWVRNNFpUVTVabVptT1NJc0luQjFZbXhwWTE5clpYa2lPaUpOUTI5M1FsRlpSRXN5Vm5kQmVVVkJObVE1WWxGUlJuVkZibFU0ZGxOdGVEbG1SRzh3VjNobFl6UXlTbVJPWnpSV1VqUkdUM0kwTDBKVmF6MGlMQ0oyWlhKemFXOXVJam9pTlM0d0luMD0iLCJzaWduYXR1cmVzIjpbeyJzaWduYXR1cmUiOiJNRkV3RFFZSllJWklBV1VEQkFJREJRQUVRTlhndWliWTFjRENmbnVKaFRLK2pYL1F2NnY1aTVUenFRczNlMWZXbGJpc2RVV1loK3MxMGdzTGtoZjgzd09xcm04WlhVQ3BqZ2tKbjgzVERhS1laUTg9Iiwic2lnbmVyIjoic2VsZiJ9LHsic2lnbmF0dXJlIjoiTUZFd0RRWUpZSVpJQVdVREJBSURCUUFFUU5YZ3VpYlkxY0RDZm51SmhUSytqWC9RdjZ2NWk1VHpxUXMzZTFmV2xiaXNkVVdZaCtzMTBnc0xraGY4M3dPcXJtOFpYVUNwamdrSm44M1REYUtZWlE4PSIsInNpZ25lciI6InZpcmdpbCJ9LHsic2lnbmF0dXJlIjoiTUZFd0RRWUpZSVpJQVdVREJBSURCUUFFUUZvdTFmVEZxd3FlV2hMbVpjUzNNYlB2dlVkQm1QL1F1cnF6R3p6MFR2L1RUOEQrckUzZDczZlBFdnJOeEFkeHlSd1Awd1hTV3orUFFrS2liTFV2R1FRPSIsInNpZ25lciI6ImV4dHJhIn1dfQ==")

	assert.NoError(t, err)

	model2, err := GenerateRawSignedModelFromJson(`{"content_snapshot":"eyJjcmVhdGVkX2F0IjoxNTE1Njg2MjQ1LCJpZGVudGl0eSI6InRlc3QiLCJwcmV2aW91c19jYXJkX2lkIjoiYTY2NjMxODA3MTI3NGFkYjczOGFmM2Y2N2I4YzdlYzI5ZDk1NGRlMmNhYmZkNzFhOTQyZTZlYTM4ZTU5ZmZmOSIsInB1YmxpY19rZXkiOiJNQ293QlFZREsyVndBeUVBNmQ5YlFRRnVFblU4dlNteDlmRG8wV3hlYzQySmROZzRWUjRGT3I0L0JVaz0iLCJ2ZXJzaW9uIjoiNS4wIn0=","signatures":[{"signature":"MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=","signer":"self"},{"signature":"MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=","signer":"virgil"},{"signature":"MFEwDQYJYIZIAWUDBAIDBQAEQFou1fTFqwqeWhLmZcS3MbPvvUdBmP/QurqzGzz0Tv/TT8D+rE3d73fPEvrNxAdxyRwP0wXSWz+PQkKibLUvGQQ=","signer":"extra"}]}`)

	assert.NoError(t, err)
	assert.EqualValues(t, model1, model2)

	assert.True(t, len(model1.Signatures) == 3)

	var content1 *RawCardContent
	err = ParseSnapshot(model1.ContentSnapshot, &content1)
	assert.NoError(t, err)

	var content2 *RawCardContent
	err = ParseSnapshot(model1.ContentSnapshot, &content2)
	assert.NoError(t, err)

	assert.EqualValues(t, content1, content2)

	assert.Equal(t, content1.Identity, "test")
	assert.Equal(t, content1.Version, CardVersion)
	assert.Equal(t, content1.CreatedAt, int64(1515686245))
	pub, err := base64.StdEncoding.DecodeString("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=")
	assert.NoError(t, err)
	assert.Equal(t, content1.PublicKey, pub)
	assert.Equal(t, content1.PreviousCardId, "a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9")

}
