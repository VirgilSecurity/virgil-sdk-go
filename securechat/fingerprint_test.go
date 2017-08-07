package securechat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNumberFingerprint(t *testing.T) {
	ids := []string{"b", "c", "a"}
	fp, err := NumberFingerprint(ids)
	assert.NoError(t, err)
	assert.Equal(t, "95767 63932 18392 87777 58010 79361 43185 89666 69268 33576 75875 36436", fp)
}

func BenchmarkNumberFingerprint(b *testing.B) {
	ids := []string{"b", "c", "a"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NumberFingerprint(ids)
	}
}
