package o3

import (
	"encoding"
	mrand "math/rand"
	"time"
)

// MsgType determines the type of message that is sent or received. Users usually
// won't use this directly and rather use message generator functions.
type MsgType uint8

//TODO: figure these out
type msgFlags struct {
	PushMessage                    bool
	NoQueuing                      bool
	NoAckExpected                  bool
	MessageHasAlreadyBeenDelivered bool
	GroupMessage                   bool
}

// NewMsgID returns a randomly generated message ID (not cryptographically secure!)
// TODO: Why mrand?
func NewMsgID() uint64 {
	mrand.Seed(int64(time.Now().Nanosecond()))
	msgID := uint64(mrand.Int63())
	return msgID
}

type Message interface {
	encoding.BinaryMarshaler

	Header() *MessageHeader
}

// Message representing the various kinds of e2e ecrypted messages threema supports
type MessageHeader struct {
	Sender    IDString
	Recipient IDString
	ID        uint64
	Time      time.Time
	PubNick   PubNick
}

func NewMessageHeader(sc *SessionContext, recipient string) *MessageHeader {
	recipientID := NewIDString(recipient)

	return &MessageHeader{
		Sender:    sc.ID.ID,
		Recipient: recipientID,
		ID:        NewMsgID(),
		Time:      time.Now(),
		PubNick:   sc.ID.Nick,
	}
}

func (mh *MessageHeader) Header() *MessageHeader {
	return mh
}

var messageUnmarshal map[MsgType]func(*MessageHeader, []byte) (Message, error)

func init() {
	messageUnmarshal = make(map[MsgType]func(*MessageHeader, []byte) (Message, error))
}
