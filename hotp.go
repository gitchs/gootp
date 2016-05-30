//
// hotp.go
// Copyright (C) 2016 tinyproxy <tinyproxy@rmbp.haisong.me>
//
// Distributed under terms of the MIT license.
//
// For more info, please visit https://tools.ietf.org/html/rfc4226

package gootp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"strconv"
)

// HOTP implementation
type HOTP struct {
	secret []byte
	digits int
}

// At generate code
func (h HOTP) At(counter uint64) string {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	hash := hmac.New(sha1.New, h.secret)
	hash.Write(counterBytes)
	hs := hash.Sum(nil)
	offset := hs[19] & 0x0f
	binCodeBytes := make([]byte, 4)
	binCodeBytes[0] = hs[offset] & 0x7f
	binCodeBytes[1] = hs[offset+1] & 0xff
	binCodeBytes[2] = hs[offset+2] & 0xff
	binCodeBytes[3] = hs[offset+3] & 0xff
	binCode := binary.BigEndian.Uint32(binCodeBytes)
	mod := uint32(1)
	for i := 0; i < h.digits; i++ {
		mod *= 10
	}
	code := binCode % mod
	codeString := strconv.FormatUint(uint64(code), 10)
	if len(codeString) < h.digits {
		paddingByteLength := h.digits - len(codeString)
		paddingBytes := make([]byte, paddingByteLength)
		for i := 0; i < paddingByteLength; i++ {
			paddingBytes[i] = '0'
		}
		codeString = string(paddingBytes) + codeString
	}
	return codeString
}

// Verify verify OTP code
func (h HOTP) Verify(code string, counter uint64) bool {
	realCode := h.At(counter)
	if realCode == code {
		return true
	}
	return false
}

// NewHOTP generate new HOTP instance
func NewHOTP(secret []byte, digits int) (h *HOTP) {
	h = new(HOTP)
	h.secret = secret
	h.digits = digits
	return
}
