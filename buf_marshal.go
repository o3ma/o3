package o3

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
)

func bufMarshal(context string, buf *bytes.Buffer, i interface{}) {
	err := binary.Write(buf, binary.LittleEndian, i)
	if err != nil {
		panic(fmt.Sprintf("%s: %s", context, err))
	}
}

// bufMarshalPadding returns a byte slice filled with n repetitions of the byte value n
func bufMarshalPadding(buf *bytes.Buffer) {
	paddingValueBig, err := rand.Int(rand.Reader, big.NewInt(255))
	if err != nil {
		panic(err)
	}
	paddingValue := byte(paddingValueBig.Int64())
	padding := make([]byte, paddingValue)
	for i := range padding {
		padding[i] = paddingValue
	}
	bufMarshal("padding", buf, padding)
}

func bugMarshalByte(context string, buf *bytes.Buffer, b byte) {
	err := buf.WriteByte(b)
	if err != nil {
		panic(fmt.Sprintf("%s: %s", context, err))
	}
}
