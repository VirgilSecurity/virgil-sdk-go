package virgil

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v5/errors"
)

func TestNewCreateCardRequest_CheckCorrectStructFilling(t *testing.T) {
	crypto := Crypto()
	paier, _ := crypto.GenerateKeypair()

	pk, _ := paier.PublicKey().Encode()
	expected := CardModel{
		Identity:     "test",
		IdentityType: "application",
		PublicKey:    pk,
		Scope:        CardScope.Application,
		Data: map[string]string{
			"test": "test data",
		},
		DeviceInfo: &DeviceInfo{
			Device:     "test device",
			DeviceName: "my device",
		},
	}

	r, _ := NewCreateCardRequest("test", "application", paier.PublicKey(), CardParams{
		Scope:      expected.Scope,
		Data:       expected.Data,
		DeviceInfo: expected.DeviceInfo,
	})

	var actual CardModel
	json.Unmarshal(r.Snapshot, &actual)

	assert.Equal(t, expected, actual)
}

func TestNewCreateCardRequest_ScopeEmpty_SetScopeApplication(t *testing.T) {
	crypto := Crypto()
	paier, _ := crypto.GenerateKeypair()

	r, _ := NewCreateCardRequest("test", "application", paier.PublicKey(), CardParams{})

	var actual CardModel
	json.Unmarshal(r.Snapshot, &actual)

	assert.Equal(t, CardScope.Application, actual.Scope)
}

type FakePublicKey struct {
}

func (k *FakePublicKey) Encode() ([]byte, error) {
	return nil, errors.New("Error")
}

func (k *FakePublicKey) Empty() bool {
	return false
}

func (k *FakePublicKey) ReceiverID() []byte {
	return make([]byte, 0)
}

func (k *FakePublicKey) contents() []byte {
	return make([]byte, 0)
}

func TestNewCreateCardRequest_PublicKeyEncodeReturnErr_ReturnErr(t *testing.T) {

	r, err := NewCreateCardRequest("identity", "identityType", &FakePublicKey{}, CardParams{})
	assert.Nil(t, r)
	assert.NotNil(t, err)
}

func TestNewRevokeCardRequest_CheckCorrectStructFilling(t *testing.T) {
	expected := RevokeCardRequest{
		ID:               "id",
		RevocationReason: RevocationReason.Compromised,
	}
	r, _ := NewRevokeCardRequest("id", RevocationReason.Compromised)

	var actual RevokeCardRequest
	json.Unmarshal(r.Snapshot, &actual)

	assert.Equal(t, expected, actual)
}

func TestAppendSignature_SignWasAdd(t *testing.T) {
	r, _ := NewRevokeCardRequest("id", RevocationReason.Compromised)
	r.AppendSignature("test", []byte(`test sign`))

	v, ok := r.Meta.Signatures["test"]

	assert.True(t, ok)
	assert.Equal(t, []byte(`test sign`), v)
}

func TestExportCreateCardRequest(t *testing.T) {
	skText := "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBBY2VC00M5TXq8+OOZSYg6ZAgITCzAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEBIKyYaNGCpz2R0HiAOVgB4EQB3xDjwxWHmCOOXItuyFWXvwlqjV3rasLEklUJ/aMYDCh+YaqqDLlxiVWKCm4Idn3sp+0N0OLhoqJVoKskFI+oU="
	pkText := "MCowBQYDK2VwAyEAMBZKyQeskY3fA6FU2/6pB5GWVJII53pLs2t6HWU1SiA="
	expected := "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkluUmxjM1JBYldGcGJDNWpiMjBpTENKcFpHVnVkR2wwZVY5MGVYQmxJam9pWlcxaGFXd2lMQ0p3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVUxQ1drdDVVV1Z6YTFrelprRTJSbFV5THpad1FqVkhWMVpLU1VrMU0zQk1jekowTmtoWFZURlRhVUU5SWl3aWMyTnZjR1VpT2lKbmJHOWlZV3dpTENKa1lYUmhJanA3SW10bGVURWlPaUoyWVd4MVpURWlMQ0pyWlhreUlqb2lkbUZzZFdVeUlpd2lhMlY1TXlJNkluWmhiSFZsTXlJc0ltdGxlVFFpT2lKMllXeDFaVFFpZlN3aWFXNW1ieUk2ZXlKa1pYWnBZMlVpT2lKcFVHaHZibVVpTENKa1pYWnBZMlZmYm1GdFpTSTZJamNpZlgwPSIsIm1ldGEiOnsic2lnbnMiOnsiNTY1MGEzMjljM2RiNmViYmVkM2M2ZjA3MjQ4MjliNjczOGY0NzJkNzY5MzQwMmZkMmZkMGNhMTRlZmVmMjllYSI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFIQktTL292K3ZGblI5Z1Y0bXdBZGZjSmM4RDJxK3c5WmpUOFZXTytwVFh3eXVQT1F0Zm5NZHh0cHZtY1BhdU0xOGVjYXl3d3BpbUNVbkZ4SVhhZG1RWT0iLCJhN2M2Y2I0ZmQ4MDBhM2QyMTg3ZDVlMzQyZjM2YTJjMDRiMzQzMjE5MTJjMjMwYjYwNjllNjEyMjI2NDVmYiI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFIQktTL292K3ZGblI5Z1Y0bXdBZGZjSmM4RDJxK3c5WmpUOFZXTytwVFh3eXVQT1F0Zm5NZHh0cHZtY1BhdU0xOGVjYXl3d3BpbUNVbkZ4SVhhZG1RWT0ifX19"

	pass := "p@sS\\/\\/0rD"

	sk, err := Crypto().ImportPrivateKey([]byte(skText), pass)
	assert.Nil(t, err)

	pk, err := Crypto().ImportPublicKey([]byte(pkText))
	assert.Nil(t, err)

	req, _ := NewCreateCardRequest("test@mail.com", "email", pk, CardParams{
		Scope: CardScope.Global,
		Data: map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
			"key4": "value4",
		},
		DeviceInfo: &DeviceInfo{
			Device:     "iPhone",
			DeviceName: "7",
		},
	},
	)

	req.SelfSign(sk)
	req.AuthoritySign("a7c6cb4fd800a3d2187d5e342f36a2c04b34321912c230b6069e61222645fb", sk)
	rez, err := req.Export()
	assert.Nil(t, err)
	assert.Equal(t, expected, string(rez))
}

func TestImportCreateCardRequest(t *testing.T) {
	skText := "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBBY2VC00M5TXq8+OOZSYg6ZAgITCzAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEBIKyYaNGCpz2R0HiAOVgB4EQB3xDjwxWHmCOOXItuyFWXvwlqjV3rasLEklUJ/aMYDCh+YaqqDLlxiVWKCm4Idn3sp+0N0OLhoqJVoKskFI+oU="
	pkText := "MCowBQYDK2VwAyEAMBZKyQeskY3fA6FU2/6pB5GWVJII53pLs2t6HWU1SiA="
	exported := "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNkluUmxjM1JBYldGcGJDNWpiMjBpTENKcFpHVnVkR2wwZVY5MGVYQmxJam9pWlcxaGFXd2lMQ0p3ZFdKc2FXTmZhMlY1SWpvaVRVTnZkMEpSV1VSTE1sWjNRWGxGUVUxQ1drdDVVV1Z6YTFrelprRTJSbFV5THpad1FqVkhWMVpLU1VrMU0zQk1jekowTmtoWFZURlRhVUU5SWl3aWMyTnZjR1VpT2lKbmJHOWlZV3dpTENKa1lYUmhJanA3SW10bGVURWlPaUoyWVd4MVpURWlMQ0pyWlhreUlqb2lkbUZzZFdVeUlpd2lhMlY1TXlJNkluWmhiSFZsTXlJc0ltdGxlVFFpT2lKMllXeDFaVFFpZlN3aWFXNW1ieUk2ZXlKa1pYWnBZMlVpT2lKcFVHaHZibVVpTENKa1pYWnBZMlZmYm1GdFpTSTZJamNpZlgwPSIsIm1ldGEiOnsic2lnbnMiOnsiNTY1MGEzMjljM2RiNmViYmVkM2M2ZjA3MjQ4MjliNjczOGY0NzJkNzY5MzQwMmZkMmZkMGNhMTRlZmVmMjllYSI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFIQktTL292K3ZGblI5Z1Y0bXdBZGZjSmM4RDJxK3c5WmpUOFZXTytwVFh3eXVQT1F0Zm5NZHh0cHZtY1BhdU0xOGVjYXl3d3BpbUNVbkZ4SVhhZG1RWT0iLCJhN2M2Y2I0ZmQ4MDBhM2QyMTg3ZDVlMzQyZjM2YTJjMDRiMzQzMjE5MTJjMjMwYjYwNjllNjEyMjI2NDVmYiI6Ik1GRXdEUVlKWUlaSUFXVURCQUlDQlFBRVFIQktTL292K3ZGblI5Z1Y0bXdBZGZjSmM4RDJxK3c5WmpUOFZXTytwVFh3eXVQT1F0Zm5NZHh0cHZtY1BhdU0xOGVjYXl3d3BpbUNVbkZ4SVhhZG1RWT0ifX19"

	pass := "p@sS\\/\\/0rD"

	sk, err := Crypto().ImportPrivateKey([]byte(skText), pass)
	assert.Nil(t, err)

	pk, err := Crypto().ImportPublicKey([]byte(pkText))
	assert.Nil(t, err)

	imported, err := ImportCreateCardRequest([]byte(exported))

	assert.Nil(t, err)

	req, _ := NewCreateCardRequest("test@mail.com", "email", pk, CardParams{
		Scope: CardScope.Global,
		Data: map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
			"key4": "value4",
		},
		DeviceInfo: &DeviceInfo{
			Device:     "iPhone",
			DeviceName: "7",
		},
	},
	)

	req.SelfSign(sk)
	req.AuthoritySign("a7c6cb4fd800a3d2187d5e342f36a2c04b34321912c230b6069e61222645fb", sk)

	assert.Equal(t, req, imported)

}

func TestExportRevokeCardRequest(t *testing.T) {
	skText := "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBCvzSjIig/xPnx2jdyscOQIAgIX2zAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEAYf9kgEHaG7DtL909qQdfMEQL+iurX2A2mM87hqkdrdOX4KyZjp79m8RMeyQU1+0r5FVIQp/DFHi+WWaU7KvO0gVC0FCCS8tsltxlxOd1W4HzA="
	expected := "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKallYSmtYMmxrSWpvaU1qTTBOakl6T1RnME56WXlPVGd6TnpRMk1qazROek0wSWl3aWNtVjJiMk5oZEdsdmJsOXlaV0Z6YjI0aU9pSmpiMjF3Y205dGFYTmxaQ0o5IiwibWV0YSI6eyJzaWducyI6eyIyMjM0ZjIzNGYyMzRmMjM0ZjIzNDIzNGYiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRTjN5ZG1ZY3F2QWZ6elJ4eHc4UHJ2NHpHQ1lNSXhZcjlINjdEcGRKM1BMUXFxa1Y5U3BiOUhGck00Zk42Q3BTWmIvNC9lMmZ4ejZ2bG1Yd3dsT3pwQTA9In19fQ=="

	pass := "p@sS\\/\\/0rD"

	sk, err := Crypto().ImportPrivateKey([]byte(skText), pass)
	assert.Nil(t, err)

	req, err := NewRevokeCardRequest("234623984762983746298734", RevocationReason.Compromised)
	assert.Nil(t, err)

	req.AuthoritySign("2234f234f234f234f234234f", sk)
	rez, err := req.Export()
	assert.Nil(t, err)
	assert.Equal(t, expected, string(rez))
}

func TestImportRevokeCardRequest(t *testing.T) {
	skText := "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBCvzSjIig/xPnx2jdyscOQIAgIX2zAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEAYf9kgEHaG7DtL909qQdfMEQL+iurX2A2mM87hqkdrdOX4KyZjp79m8RMeyQU1+0r5FVIQp/DFHi+WWaU7KvO0gVC0FCCS8tsltxlxOd1W4HzA="
	exported := "eyJjb250ZW50X3NuYXBzaG90IjoiZXlKallYSmtYMmxrSWpvaU1qTTBOakl6T1RnME56WXlPVGd6TnpRMk1qazROek0wSWl3aWNtVjJiMk5oZEdsdmJsOXlaV0Z6YjI0aU9pSmpiMjF3Y205dGFYTmxaQ0o5IiwibWV0YSI6eyJzaWducyI6eyIyMjM0ZjIzNGYyMzRmMjM0ZjIzNDIzNGYiOiJNRkV3RFFZSllJWklBV1VEQkFJQ0JRQUVRTjN5ZG1ZY3F2QWZ6elJ4eHc4UHJ2NHpHQ1lNSXhZcjlINjdEcGRKM1BMUXFxa1Y5U3BiOUhGck00Zk42Q3BTWmIvNC9lMmZ4ejZ2bG1Yd3dsT3pwQTA9In19fQ=="

	pass := "p@sS\\/\\/0rD"

	sk, err := Crypto().ImportPrivateKey([]byte(skText), pass)
	assert.Nil(t, err)

	imported, err := ImportRevokeCardRequest([]byte(exported))
	assert.Nil(t, err)

	req, err := NewRevokeCardRequest("234623984762983746298734", RevocationReason.Compromised)
	assert.Nil(t, err)

	req.AuthoritySign("2234f234f234f234f234234f", sk)
	assert.Equal(t, imported, req)
}
