package common

var (
	invalidXorParamsMessage = "invalid input for xor function - the both arguments must have the same length"
)

const (
	Msb = 0b10000000
	blockSize = 16
	firstPaddingOctet = 0b10000000
)

func Xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic(invalidXorParamsMessage)
	}
	result := make([]byte, len(a))

	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result
}

func ShiftLeft(data []byte) []byte {
	bit := byte(0)

	result := make([]byte, len(data))
	for i := len(data) - 1; i >= 0; i-- {
		result[i] = (data[i] << 1) | bit
		bit = (data[i] & Msb) >> 7
	}

	return result
}

func Padding(data []byte) []byte {
	result := data
	result = append(result, firstPaddingOctet)
	if len(result) < blockSize {
		n := len(result)
		for i := 0; i < blockSize-n; i++ {
			result = append(result, 0x00)
		}
	}

	return result
}
