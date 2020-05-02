package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"github.com/luc-lynx/siv/common"
	"hash"
)

const (
	blockSize = 16
)

var (
	zero = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	rb = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
	}

	errUnsupportedKeySize = errors.New("key size is not supported")
	errAlreadyFinished    = errors.New("the processing has been finalized, reset call is needed")
)

type cmac struct {
	aesEncryptor cipher.Block
	state        []byte
	key          []byte
	accumulator  []byte
	finished     bool
	hadData      bool

	k1 []byte
	k2 []byte
}

func (c *cmac) Write(p []byte) (n int, err error) {
	if c.finished {
		return 0, errAlreadyFinished
	}

	if len(p) == 0 {
		return 0, nil
	}

	c.hadData = true
	c.accumulator = append(c.accumulator, p...)
	numFullBlocks := len(c.accumulator) / blockSize

	// For the final stage we need some more data than one block
	if numFullBlocks <= 1 {
		return len(p), nil
	}

	// Leaving last block for final stage
	for i := 0; i < numFullBlocks-1; i++ {
		c.writeFullBlock(c.accumulator[0:blockSize])
		c.accumulator = c.accumulator[blockSize:]
	}

	return len(p), nil
}

func (c *cmac) writeFullBlock(block []byte) {
	c.state = common.Xor(c.state, block)
	c.aesEncryptor.Encrypt(c.state, c.state)
}

func (c cmac) Sum(b []byte) []byte {
	if c.hadData {
		if len(c.accumulator) == blockSize {
			c.accumulator = common.Xor(c.accumulator, c.k1)
		} else {
			// we've got a bit more than one block
			if len(c.accumulator) > blockSize {
				c.writeFullBlock(c.accumulator[0:blockSize])
				c.accumulator = c.accumulator[blockSize:]
			}
			c.accumulator = common.Xor(common.Padding(c.accumulator), c.k2)
		}
	} else {
		// nil array corner case
		c.accumulator = common.Xor(common.Padding([]byte{}), c.k2)
	}

	// Y = M_last XOR X
	y := common.Xor(c.accumulator, c.state)
	c.aesEncryptor.Encrypt(y, y)

	c.finished = true
	return append(b, y...)
}

func (c *cmac) Reset() {
	c.init()
}

func (c cmac) Size() int {
	return blockSize
}

func (c cmac) BlockSize() int {
	return blockSize
}

func (c *cmac) generateSubKey() ([]byte, []byte) {
	var k1 []byte
	var k2 []byte

	l := make([]byte, blockSize)
	c.aesEncryptor.Encrypt(l, zero)

	k1 = common.ShiftLeft(l)
	// MSB(l)
	if l[0]&common.Msb == common.Msb {
		k1 = common.Xor(k1, rb)
	}

	k2 = common.ShiftLeft(k1)
	if k1[0]&common.Msb == common.Msb {
		k2 = common.Xor(k2, rb)
	}
	return k1, k2
}

func (c *cmac) init() {
	c.k1, c.k2 = c.generateSubKey()
	c.accumulator = []byte{}
	c.state = make([]byte, 16)
	c.finished = false
	c.hadData = false
}

func NewCmac(key []byte) (hash.Hash, error) {
	switch len(key) {
	case 16, 24, 32:
		break
	default:
		return nil, errUnsupportedKeySize
	}

	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := &cmac{
		aesEncryptor: a,
		key:          key,
	}

	result.init()
	return result, nil
}

func Sum(key, data []byte) []byte {
	c, err := NewCmac(key)
	if err != nil {
		panic(err.Error())
	}

	_, err = c.Write(data)
	if err != nil {
		panic(err.Error())
	}

	return c.Sum(nil)
}
