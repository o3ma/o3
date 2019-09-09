package o3

import (
	"bytes"
	"errors"
)

// MsgType mock enum
const (
	MessageTypeText      MsgType = 0x1
	MessageTypeGroupText MsgType = 0x41
)

//TextMessage represents a text message as sent e2e encrypted to other threema users
type TextMessage struct {
	*MessageHeader
	*GroupMessageHeader
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
func (m TextMessage) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if m.GroupMessageHeader == nil {
		bufMarshal("msg-type", buf, MessageTypeText)
	} else {
		bufMarshal("msg-type", buf, uint8(MessageTypeGroupText))
		data, err := m.GroupMessageHeader.MarshalBinary()
		bufMarshal("msg-group-header", buf, data)
		if err != nil {
			return nil, err
		}
	}
	bufMarshal("body", buf, []byte(m.Body))
	bufMarshalPadding(buf)

	return buf.Bytes(), nil
}

func (m *TextMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var t MsgType
	bufUnmarshal("read message type", buf, &t)
	if t == MessageTypeGroupText {
		m.GroupMessageHeader.UnmarshalBinary(data[1 : GroupMessageHeaderLenght+1])
	} else if t != MessageTypeText {
		return errors.New("not correct type")
	}
	stripPadding(buf)

	m.Body = string(buf.Bytes())
	return nil
}

func init() {
	messageUnmarshal[MessageTypeText] = func(mh *MessageHeader, data []byte) (Message, error) {
		m := &TextMessage{
			MessageHeader: mh,
		}
		if err := m.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return m, nil
	}
	messageUnmarshal[MessageTypeGroupText] = func(mh *MessageHeader, data []byte) (Message, error) {
		m := &TextMessage{
			MessageHeader:      mh,
			GroupMessageHeader: &GroupMessageHeader{},
		}

		if err := m.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return m, nil
	}
}
