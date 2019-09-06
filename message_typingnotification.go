package o3

import (
	"bytes"
	"errors"
	"fmt"
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
	bufMarshal("msg-type", buf, MessageTypeTypingNotification)
	bufMarshal("body", buf, msg.OnOff)
	bufMarshalPadding(buf)

	return buf.Bytes(), nil
}

func (msg *TypingNotificationMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var t MsgType
	bufUnmarshal("read message type", buf, &t)
	if t != MessageTypeTypingNotification {
		return errors.New("not correct type")
	}
	stripPadding(buf)
	bufUnmarshal("typing?", buf, &msg.OnOff)

	return nil
}
func (msg *TypingNotificationMessage) String() string {
	if msg.OnOff != 0 {
		return fmt.Sprintf("%s is composing", msg.Sender)
	}
	return fmt.Sprintf("%s is inactive", msg.Sender)
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
