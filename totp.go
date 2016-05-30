//
// totp.go
// Copyright (C) 2016 tinyproxy <tinyproxy@rmbp.haisong.me>
//
// Distributed under terms of the MIT license.
//

package gootp

import "time"

// TOTP implementation
type TOTP struct {
	*HOTP
	x int64
}

// NewTOTP generate new TOTP instance
func NewTOTP(secret []byte, digits, x int) (t *TOTP) {
	t = new(TOTP)
	t.HOTP = NewHOTP(secret, digits)
	t.x = int64(x)
	return t
}

// At get OTP at specific timestamp
func (t TOTP) At(timestamp int64) string {
	counter := uint64(timestamp / t.x)
	return t.HOTP.At(counter)
}

// Now get current TOTP
func (t TOTP) Now() string {
	now := time.Now()
	timestamp := now.Unix()
	return t.At(timestamp)
}

// Verify verify OTP code
func (t TOTP) Verify(code string) bool {
	realCode := t.Now()
	if realCode == code {
		return true
	}
	return false
}
