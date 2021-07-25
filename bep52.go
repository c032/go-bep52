package bep52

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
)

const (
	BlockSize = 16 * 1024
	Size      = sha256.Size
)

var _ hash.Hash = (*bep52)(nil)

type leafHash [Size]byte

type bep52 struct {
	buf        *bytes.Buffer
	leafHashes []leafHash
}

func (h *bep52) Write(p []byte) (int, error) {
	var (
		err     error
		written int
	)

	written, err = h.buf.Write(p)
	if err != nil {
		return written, fmt.Errorf("could not write to internal buffer: %w", err)
	}

	for h.buf.Len() >= BlockSize {
		block := make([]byte, BlockSize)

		_, err = h.buf.Read(block)
		if err != nil {
			return written, fmt.Errorf("could not read from internal buffer: %w", err)
		}

		blockHash := sha256.Sum256(block)
		h.leafHashes = append(h.leafHashes, blockHash)
	}

	return written, err
}

func (h *bep52) Sum(b []byte) []byte {
	leaves := append([]leafHash(nil), h.leafHashes...)

	if h.buf.Len() > 0 {
		lastHash := sha256.Sum256(h.buf.Bytes())
		leaves = append(leaves, lastHash)
	}

	currentLeaves := len(leaves)

	expectedLeaves := 1
	for expectedLeaves < currentLeaves {
		expectedLeaves = expectedLeaves << 1
	}

	currentLayer := make([]leafHash, expectedLeaves)
	for i, leaf := range leaves {
		currentLayer[i] = leaf
	}

	// Sanity check.
	if len(currentLayer)%2 != 0 {
		panic("Expected `currentLayer` to have an even length.")
	}

	for len(currentLayer) > 1 {
		nextLayer := make([]leafHash, 0, len(currentLayer)/2)
		for i := 0; i < len(currentLayer); i += 2 {
			left := []byte(currentLayer[i][:])
			right := []byte(currentLayer[i+1][:])

			var data []byte

			data = append(data, left...)
			data = append(data, right...)

			dataSum := sha256.Sum256(data)

			nextLayer = append(nextLayer, dataSum)
		}

		// Sanity check.
		if len(nextLayer) >= len(currentLayer) {
			panic("Expected `nextLayer` to be smaller than `currentLayer`.")
		}

		currentLayer = nextLayer
	}

	return currentLayer[0][:]
}

func (h *bep52) Reset() {
	h.buf = &bytes.Buffer{}
	h.leafHashes = nil
}

func (h *bep52) Size() int {
	return Size
}

func (h *bep52) BlockSize() int {
	return BlockSize
}

func New() hash.Hash {
	return &bep52{
		buf: &bytes.Buffer{},
	}
}
