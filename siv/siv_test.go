package siv

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"testing"
)

/*
Test Vectors for AES-SIV from Appendix A RFC 5297
https://tools.ietf.org/html/rfc5297#appendix-A
*/

func TestAesSiv(t *testing.T) {
	t.Run("bitAnd with mask", testBitAnd)
	t.Run("dbl", testDouble)
	t.Run("seal", testSeal)
	t.Run("open", testOpen)
	t.Run("seal/open (256 bit each key)", testSeal256)
	t.Run("random seal/open (256 bits)", func(t *testing.T) {
		testRandomSealOpen(t, 32)
	})
	t.Run("random seal/open (384 bits)", func(t *testing.T) {
		testRandomSealOpen(t, 48)
	})
	t.Run("random seal/open (512 bits)", func(t *testing.T) {
		testRandomSealOpen(t, 64)
	})
	t.Run("bad key size test", testBadKeySize)
}

func testBitAnd(t *testing.T) {
	in := []byte{
		0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
		0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
	}

	out := []byte{
		0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
		0x15, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
	}

	result := bitAnd(in, mask)
	if subtle.ConstantTimeCompare(out, result) != 1 {
		t.Fail()
	}
}

func testDouble(t *testing.T) {
	in1 := []byte{
		0x0e, 0x04, 0xdf, 0xaf, 0xc1, 0xef, 0xbf, 0x04,
		0x01, 0x40, 0x58, 0x28, 0x59, 0xbf, 0x07, 0x3a,
	}
	out1 := []byte{
		0x1c, 0x09, 0xbf, 0x5f, 0x83, 0xdf, 0x7e, 0x08,
		0x02, 0x80, 0xb0, 0x50, 0xb3, 0x7e, 0x0e, 0x74,
	}
	in2 := []byte{
		0xed, 0xf0, 0x9d, 0xe8, 0x76, 0xc6, 0x42, 0xee,
		0x4d, 0x78, 0xbc, 0xe4, 0xce, 0xed, 0xfc, 0x4f,
	}
	out2 := []byte{
		0xdb, 0xe1, 0x3b, 0xd0, 0xed, 0x8c, 0x85, 0xdc,
		0x9a, 0xf1, 0x79, 0xc9, 0x9d, 0xdb, 0xf8, 0x19,
	}

	result1 := dbl(in1)
	if subtle.ConstantTimeCompare(out1, result1) != 1 {
		t.Fail()
		return
	}

	result2 := dbl(in2)
	if subtle.ConstantTimeCompare(out2, result2) != 1 {
		t.Fail()
	}
}

var (
	key = []byte{
		0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
		0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	}

	ad = []byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	}

	plaintext = []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
	}

	ciphertext = []byte{
		0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
		0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
		0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
		0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c,
	}

	key512 = []byte{
		0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
		0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
		0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
		0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	}
)

func testSeal(t *testing.T) {
	enc, err := NewAesSIV(key)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}

	ct := enc.Seal(nil, nil, plaintext, ad)
	if subtle.ConstantTimeCompare(ciphertext, ct) != 1 {
		t.Fail()
	}
}

func testOpen(t *testing.T) {
	enc, err := NewAesSIV(key)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}

	pt, err := enc.Open(nil, nil, ciphertext, ad)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	if subtle.ConstantTimeCompare(pt, plaintext) != 1 {
		t.Fail()
	}
}

func testSeal256(t *testing.T) {
	enc, err := NewAesSIV(key512)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	ct := enc.Seal(nil, nil, plaintext, ad)
	pt2, err := enc.Open(nil, nil, ct, ad)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	if subtle.ConstantTimeCompare(pt2, plaintext) != 1 {
		t.Fail()
	}
}

func runSealOpen(key, plaintext []byte, aad [][]byte) error {
	s, err := NewAesSIV(key)
	if err != nil {
		return err
	}

	ct := s.SealWithMultipleAAD(nil, plaintext, aad)
	pt, err := s.OpenWithMultipleAAD(nil, ct, aad)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(pt, plaintext) != 1 {
		return errors.New("plaintext mismatch")
	}
	return nil
}

func testRandomSealOpen(t *testing.T, keyLen int) {
	// we need at least 256 bits for this mode
	key := make([]byte, keyLen)
	_, err := rand.Read(key)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	aad := [][]byte{
		make([]byte, 1),
		make([]byte, 17),
		make([]byte, 0),
		make([]byte, blockSize*2),
	}

	for i := range aad {
		if _, err := rand.Read(aad[i]); err != nil {
			t.Error(err)
			t.Fail()
			return
		}
	}

	for plaintextLen := 0; plaintextLen < 128; plaintextLen++ {
		if _, err := rand.Read(plaintext); err != nil {
			t.Error(err)
			t.Fail()
			return
		}

		err := runSealOpen(key, plaintext, aad)
		if err != nil {
			t.Error(err)
			t.Fail()
			return
		}
	}
}

func testBadKeySize(t *testing.T) {
	key := make([]byte, blockSize)
	_, err := NewAesSIV(key)
	if err == nil {
		t.Fail()
	}
}
