package o3

import (
	"bytes"

	"golang.org/x/crypto/nacl/box"
)

func newNaclReader(buf *bytes.Buffer, nonce [24]byte, peerPublicKey, privateKey [32]byte) *bytes.Buffer {

	plaintext, ok := box.Open(nil, buf.Bytes(), &nonce, &peerPublicKey, &privateKey)
	if !ok {
		panic("Cannot decrypt packet")
	}
	return bytes.NewBuffer(plaintext)
}
