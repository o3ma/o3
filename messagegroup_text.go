package o3

import (
	"bytes"
	"errors"
)

// MsgType mock enum
const MessageTypeGroupText MsgType = 0x41

type GroupMessageHeader struct {
	CreatorID IDString
	GroupID   [8]byte
}

const GroupMessageHeaderLenght = 16

func (msg *GroupMessageHeader) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	bufUnmarshal("read group creator", buf, &msg.CreatorID)
	bufUnmarshal("read group id", buf, &msg.GroupID)

	return nil
}

//GroupTextMessage represents a text message as sent e2e encrypted to other threema users
type GroupTextMessage struct {
	*GroupMessageHeader
	*TextMessage
}

//Serialize returns a fully serialized byte slice of a TextMessage
func (msg GroupTextMessage) MarshalBinary() ([]byte, error) {

	buf := new(bytes.Buffer)
	bufMarshal("msg-type", buf, uint8(MessageTypeGroupText))
	data, err := msg.TextMessage.MarshalBinary()
	if err != nil {
		return nil, err
	}
	bufMarshal("text-msg", buf, data)

	return buf.Bytes(), nil
}

func (msg *GroupTextMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var t MsgType
	bufUnmarshal("read message type", buf, &t)
	if t != MessageTypeGroupText {
		return errors.New("not correct type")
	}

	return nil
}

func init() {
	messageUnmarshal[MessageTypeGroupText] = func(mh *MessageHeader, data []byte) (Message, error) {
		tm := &GroupTextMessage{
			GroupMessageHeader: &GroupMessageHeader{},
			TextMessage: &TextMessage{
				MessageHeader: mh,
			},
		}
		data[0] = byte(MessageTypeText)
		tm.GroupMessageHeader.UnmarshalBinary(data[1 : GroupMessageHeaderLenght+1])
		data = append(data[:1], data[GroupMessageHeaderLenght+1:]...)
		tm.TextMessage.UnmarshalBinary(data)
		return tm, nil
	}
}
