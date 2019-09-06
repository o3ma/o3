package o3

import (
	"bytes"
	"errors"
)

// MsgType mock enum
const MessageTypeText MsgType = 0x1

//TextMessage represents a text message as sent e2e encrypted to other threema users
type TextMessage struct {
	*MessageHeader
	Body string
}

// NewTextMessage returns a TextMessage ready to be encrypted
func NewTextMessage(sc *SessionContext, recipient string, text string) (TextMessage, error) {
	return TextMessage{
		MessageHeader: NewMessageHeader(sc, recipient),
		Body:          text,
	}, nil
}

// String returns the message text as string
func (tm TextMessage) String() string {
	return tm.Body
}

//Serialize returns a fully serialized byte slice of a TextMessage
func (tm TextMessage) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	bufMarshal("msg-type", buf, MessageTypeText)
	bufMarshal("body", buf, []byte(tm.Body))
	bufMarshalPadding(buf)

	return buf.Bytes(), nil
}

func (tm *TextMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var t MsgType
	bufUnmarshal("read message type", buf, &t)
	if t != MessageTypeText {
		return errors.New("not correct type")
	}
	stripPadding(buf)

	tm.Body = string(buf.Bytes())
	return nil
}

func init() {
	messageUnmarshal[MessageTypeText] = func(mh *MessageHeader, data []byte) (Message, error) {
		tm := &TextMessage{
			MessageHeader: mh,
		}
		if err := tm.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return tm, nil
	}
}
