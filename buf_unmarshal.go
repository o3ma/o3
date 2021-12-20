package o3

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func stripPadding(buf *bytes.Buffer) {
	paddingLen := int(buf.Bytes()[buf.Len()-1])
	buf.Truncate(buf.Len() - paddingLen)
}

func bufUnmarshal(context string, buf *bytes.Buffer, i interface{}) {
	if err := binary.Read(buf, binary.LittleEndian, i); err != nil {
		panic(fmt.Sprintf("%s: %s", context, err))
	}
}

//helper function: not to be called directly
func bufUnmarshalBytes(buf *bytes.Buffer, size int) []byte {
	b := make([]byte, size)
	n, err := buf.Read(b)
	if n != size || err != nil {
		panic(fmt.Sprintf("%d bytes of data", size))
	}
	return b
}
