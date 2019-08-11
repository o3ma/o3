package o3

import (
	"bytes"
	"errors"
)

// MsgType mock enum
const MessageTypeTypingNotification MsgType = 0x90

//TextMessage represents a text message as sent e2e encrypted to other threema users
type TypingNotificationMessage struct {
	*MessageHeader
	OnOff byte
}

//Serialize returns a fully serialized byte slice of a TextMessage
func (msg TypingNotificationMessage) MarshalBinary() ([]byte, error) {

	buf := new(bytes.Buffer)
	bufMarshal("msg-type", buf, uint8(MessageTypeText))
	bufMarshal("body", buf, msg.OnOff)
	bufMarshalPadding(buf)

	return buf.Bytes(), nil
}

//TODO untested
func (msg *TypingNotificationMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var t MsgType
	bufUnmarshal("read message type", buf, &t)
	if t != MessageTypeTypingNotification {
		return errors.New("not correct type")
	}
	stripPadding(buf)
	bufMarshal("typing?", buf, &msg.OnOff)

	return nil
}

func init() {
	messageUnmarshal[MessageTypeTypingNotification] = func(mh *MessageHeader, data []byte) (Message, error) {
		tm := &TypingNotificationMessage{
			MessageHeader: mh,
		}
		if err := tm.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return tm, nil
	}
}
