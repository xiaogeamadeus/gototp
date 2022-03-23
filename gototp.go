package gototp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/base32"
	"time"
)

func TOTP(k string, t0, x uint64) int {
	key, err := base32.StdEncoding.DecodeString(k)
	if err != nil {
		return 0
	}
	return HOTP(key, T(0, x))
}

func T(t0, x uint64) uint64 {
	return (uint64(time.Now().Unix()) - t0) / x
}

func HMACSHA1(k []byte, c uint64) []byte {
	cb := make([]byte, 8)
	binary.BigEndian.PutUint64(cb, c)

	mac := hmac.New(sha1.New, k)
	mac.Write(cb)

	return mac.Sum(nil)
}

func TRUNCATE(hs []byte) int {
	offsetbits := hs[19] & 0xF
	offset := int(offsetbits)
	p := hs[offset : offset+4]
	return (int(binary.BigEndian.Uint32(p)) & 0x7FFFFFFF) %1000000
}

func HOTP(k []byte, c uint64) int{
	return TRUNCATE(HMACSHA1(k, c))
}
