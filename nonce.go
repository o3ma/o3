package o3

import (
	"crypto/rand"
	"encoding/binary"
)

type nonce struct {
	nonce [24]byte
}

func (n nonce) bytes() *[24]byte {
	return &n.nonce
}

func (n nonce) byteSlice() []byte {
	return n.nonce[0:24]
}

func (n nonce) prefix() [16]byte {
	var ret [16]byte
	copy(ret[0:16], n.nonce[0:16])
	return ret
}

func (n *nonce) setPrefix(prefix [16]byte) {
	copy(n.nonce[0:16], prefix[0:16])
}

func (n *nonce) set(nonce []byte) {
	copy(n.nonce[0:24], nonce)
}

func (n nonce) counter() uint64 {
	return binary.LittleEndian.Uint64(n.nonce[16:24])
}

func (n *nonce) setCounter(c uint64) {
	binary.LittleEndian.PutUint64(n.nonce[16:24], c)
}

func (n *nonce) increaseCounter() {
	binary.LittleEndian.PutUint64(n.nonce[16:24], binary.LittleEndian.Uint64(n.nonce[16:24])+1)
}

func (n *nonce) initialize(prefix [16]byte, c uint64) {
	n.setPrefix(prefix)
	n.setCounter(c)
}

// NewRandomNonce returns a fully random 24-byte nonce
func newRandomNonce() nonce {
	var n nonce
	if _, err := rand.Read(n.nonce[0:24]); err != nil {
		//Error.Println(err)
	}
	return n
}

// NewNonce returns a new 16-byte nonce with
// a counter value set to 1.
func newNonce() nonce {
	var n nonce
	if _, err := rand.Read(n.nonce[0:16]); err != nil {
		//Error.Println(err)
	}
	n.setCounter(1)
	return n
}

// NewPrefixedNonce returns a new Nonce with the given prefix the
// counter set to 1
func newPrefixedNonce(prefix [16]byte) nonce {
	var n nonce
	n.initialize(prefix, 1)
	return n
}
