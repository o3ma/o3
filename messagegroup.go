package o3

import (
	"bytes"
)

type GroupMessageHeader struct {
	CreatorID IDString
	GroupID   [8]byte
}

const GroupMessageHeaderLenght = 16

func (msg GroupMessageHeader) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	bufMarshal("gh-creator id", buf, msg.CreatorID)
	bufMarshal("gh-group id", buf, msg.GroupID)
	return buf.Bytes(), nil
}

func (msg *GroupMessageHeader) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	bufUnmarshal("read group creator", buf, &msg.CreatorID)
	bufUnmarshal("read group id", buf, &msg.GroupID)

	return nil
}
