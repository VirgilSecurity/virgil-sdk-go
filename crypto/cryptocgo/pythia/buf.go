/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package pythia

// #include "virgil/crypto/pythia/virgil_pythia_c.h"
import "C"

// Buf is needed to pass memory from Go to C and back
type Buf struct {
	inBuf *C.pythia_buf_t
	data  []byte
}

// NewBuf allocates memory block of predefined size
func NewBuf(size int) *Buf {
	p := make([]byte, size)
	buf := C.pythia_buf_new()
	C.pythia_buf_setup(buf, (*C.uint8_t)(&p[0]), C.size_t(size), C.size_t(0))
	return &Buf{
		inBuf: buf,
		data:  p,
	}
}

// NewBufWithData allocates new buffer and sets it memory to data
func NewBufWithData(data []byte) *Buf {
	buf := C.pythia_buf_new()
	C.pythia_buf_setup(buf, (*C.uint8_t)(&data[0]), C.size_t(len(data)), C.size_t(len(data)))
	return &Buf{
		inBuf: buf,
		data:  data,
	}
}

// GetData returns as many bytes as were written to buf by C code
func (b *Buf) GetData() []byte {
	newSize := int(b.inBuf.len)
	if newSize > len(b.data) {
		newSize = len(b.data)
	}
	return b.data[:newSize]
}

// Close frees memory allocated by Buf in C code
func (b *Buf) Close() {
	C.pythia_buf_free(b.inBuf)
}
