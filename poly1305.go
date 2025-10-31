package poly1305

import (
	"encoding/binary"
	"math/big"
)

const blockSize = 16

var p = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))

type MAC struct {
	r *big.Int
	s *big.Int
}

func New(r, s [16]byte) *MAC {
	m := &MAC{}

	rBytes := make([]byte, 16)
	copy(rBytes, r[:])
	rBytes[3] &= 0x0f
	rBytes[4] &= 0xfc
	rBytes[7] &= 0x0f
	rBytes[8] &= 0xfc
	rBytes[11] &= 0x0f
	rBytes[12] &= 0xfc
	rBytes[15] &= 0x0f

	m.r = readLittleEndian(rBytes)
	m.s = readLittleEndian(s[:])

	return m
}

func readLittleEndian(b []byte) *big.Int {
	result := new(big.Int)
	for i := 0; i < len(b); i += 8 {
		end := min(i+8, len(b))
		chunk := make([]byte, 8)
		copy(chunk, b[i:end])
		val := binary.LittleEndian.Uint64(chunk)
		shifted := new(big.Int).SetUint64(val)
		shifted.Lsh(shifted, uint(i*8))
		result.Or(result, shifted)
	}

	return result
}

func writeLittleEndian(dst []byte, val *big.Int) {
	for i := 0; i < len(dst); i += 8 {
		v := new(big.Int).Rsh(val, uint(i*8)).Uint64()
		binary.LittleEndian.PutUint64(dst[i:i+8], v)
	}
}

func (h *MAC) Size() int {
	return 16
}

func (m *MAC) Sum(msg []byte) []byte {
	a := big.NewInt(0)

	for i := 0; i < len(msg); i += blockSize {
		end := i + blockSize
		if end > len(msg) {
			end = len(msg)
		}
		block := msg[i:end]

		nBytes := make([]byte, len(block)+1)
		copy(nBytes, block)
		nBytes[len(block)] = 0x01

		n := readLittleEndian(nBytes)

		a.Add(a, n)
		a.Mul(a, m.r)
		a.Mod(a, p)
	}

	a.Add(a, m.s)

	// 下位128ビットだけを取得
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	a.And(a, mask)

	result := make([]byte, 16)
	writeLittleEndian(result, a)

	return result
}
