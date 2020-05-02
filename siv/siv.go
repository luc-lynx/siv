package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"github.com/luc-lynx/siv/cmac"
	"github.com/luc-lynx/siv/common"
)

/*
Implementation of Deterministic AES-SIV defined in https://tools.ietf.org/html/rfc5297
AES is used in CTR mode
S2V uses AES-CMAC mode
AAD is only authenticated and not encrypted at all (more information about AAD can be found in section 2.1
https://tools.ietf.org/html/rfc5116

Some considerations about the mode cn be found at
https://crypto.stackexchange.com/questions/59076/aes-pmac-siv-ae-algorithm
*/

var (
	errKeySizeNotSupported     = errors.New("key size not supported")
	errInvalidCiphertextLength = errors.New("invalid ciphertext length")
	errIntegrityError          = errors.New("integrity error")
	mask                       = []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff,
	}
	one = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	zero = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	rb = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
	}
)

const (
	xorEndInvalidParameters = "invalid parameters for xorEnd function, len(a) must be greater or equal than len(b)"
	bitAndInvalidParameters = "invalid parameters for bitEnd function, len(a) must be equal to len(b)"
	blockSize               = 16
)

type aessiv struct {
	cipher.AEAD
	key []byte
}

func (a aessiv) NonceSize() int {
	/*
		We don't need any external nonce for SIV as SIV generates nonce itself
	*/
	return 0
}

func (a aessiv) Overhead() int {
	/*
		IV = 128 bits
	*/
	return blockSize
}

func (a aessiv) SealWithMultipleAAD(dst, plaintext []byte, additionalData [][]byte) []byte {
	sivKey := a.key[0 : len(a.key)/2]
	encKey := a.key[len(a.key)/2:]

	v := s2v(sivKey, additionalData, plaintext)
	iv := bitAnd(v, mask)
	dst = append(dst, v...)

	aesEcb, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err.Error())
	}

	enc := cipher.NewCTR(aesEcb, iv)
	ciphertext := make([]byte, len(plaintext))
	enc.XORKeyStream(ciphertext, plaintext)

	return append(dst, ciphertext...)
}

func (a aessiv) OpenWithMultipleAAD(dst, ciphertext []byte, additionalData [][]byte) ([]byte, error) {
	if len(ciphertext) < blockSize+1 {
		return nil, errInvalidCiphertextLength
	}

	v := ciphertext[0:blockSize]
	c := ciphertext[blockSize:]
	k1 := a.key[0 : len(a.key)/2]
	k2 := a.key[len(a.key)/2:]

	iv := bitAnd(v, mask)
	aesEcb, err := aes.NewCipher(k2)
	if err != nil {
		panic(err.Error())
	}

	enc := cipher.NewCTR(aesEcb, iv)

	plaintext := make([]byte, len(c))
	enc.XORKeyStream(plaintext, c)

	t := s2v(k1, additionalData, plaintext)
	if subtle.ConstantTimeCompare(t, v) == 1 {
		return append(dst, plaintext...), nil
	}

	return nil, errIntegrityError
}

func (a aessiv) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return a.SealWithMultipleAAD(dst, plaintext, [][]byte{additionalData})
}

func (a aessiv) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return a.OpenWithMultipleAAD(dst, ciphertext, [][]byte{additionalData})
}

func NewAesSIV(key []byte) (*aessiv, error) {
	switch len(key) {
	case 32, 48, 64:
		return &aessiv{key: key}, nil
	default:
		return nil, errKeySizeNotSupported
	}
}

func s2v(key []byte, aad [][]byte, plaintext []byte) []byte {
	if len(aad) == 0 {
		return cmac.Sum(key, one)
	}

	d := cmac.Sum(key, zero)
	for i := 0; i < len(aad); i++ {
		d = common.Xor(dbl(d), cmac.Sum(key, aad[i]))
	}

	var t []byte
	if len(plaintext) >= 16 {
		t = xorEnd(plaintext, d)
	} else {
		t = common.Xor(dbl(d), common.Padding(plaintext))
	}

	return cmac.Sum(key, t)
}

func xorEnd(a, b []byte) []byte {
	if len(a) < len(b) {
		panic(xorEndInvalidParameters)
	}

	offset := len(a) - len(b)
	result := make([]byte, len(a))
	for i := 0; i < offset; i++ {
		result[i] = a[i]
	}

	for i := 0; i < len(b); i++ {
		result[i+offset] = a[i+offset] ^ b[i]
	}

	return result
}

/*
Doubling operation described at
https://tools.ietf.org/html/rfc5297#section-2.3
*/
func dbl(d []byte) []byte {
	result := common.ShiftLeft(d)
	if d[0]&common.Msb == common.Msb {
		return common.Xor(result, rb)
	}
	return result
}

func bitAnd(a, b []byte) []byte {
	if len(a) != len(b) {
		panic(bitAndInvalidParameters)
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] & b[i]
	}
	return result
}
