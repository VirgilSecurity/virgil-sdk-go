package virgilapi

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	utfstr = "\x00\x01\x02\x03\x04\x05\x06\a\b\t\n\v\f\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\u007f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
	b64str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w=="
	hexstr = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
)

func getData() Buffer {
	buf := make([]byte, 256)
	for i := 0; i < 256; i++ {
		buf[i] = byte(i)
	}
	return BufferFromBytes(buf)
}

func TestBuffer_ToUTF8String_OK(t *testing.T) {
	s := getData().ToString()
	assert.Equal(t, utfstr, s)
}

func TestBuffer_ToHEXString_Ok(t *testing.T) {
	s := getData().ToHEXString()
	assert.Equal(t, hexstr, s)
}

func TestBuffer_ToBase64String_Ok(t *testing.T) {
	s := getData().ToBase64String()
	assert.Equal(t, b64str, s)
}

func TestBufferFromString_OK(t *testing.T) {
	buf := BufferFromString(utfstr)
	assert.Equal(t, buf, getData())
}

func TestBufferFromOtherString_NotEqual(t *testing.T) {
	buf := BufferFromString(hexstr)
	assert.NotEqual(t, buf, getData())
}

func TestBufferFromWrongHEXString_Fail(t *testing.T) {
	buf, err := BufferFromHEXString(utfstr)
	assert.Nil(t, buf)
	assert.Error(t, err)
}

func TestBufferFromHEXString_Ok(t *testing.T) {
	buf, err := BufferFromHEXString(hexstr)
	assert.Nil(t, err)
	assert.Equal(t, buf, getData())
}

func TestBufferFromWrongBase64String_Fail(t *testing.T) {
	buf, err := BufferFromBase64String(utfstr)
	assert.Nil(t, buf)
	assert.Error(t, err)
}

func TestBufferFromBase64String_Ok(t *testing.T) {
	buf, err := BufferFromBase64String(b64str)
	assert.Nil(t, err)
	assert.Equal(t, buf, getData())
}
