package o3

import (
	"bytes"
	"errors"
)

// MsgType mock enum
const MessageTypeDeliveryReceipt MsgType = 0x80

// MsgStatus represents the single-byte status field of DeliveryReceiptMessage
type MsgStatus uint8

//MsgStatus mock enum
const (
	MSGDELIVERED   MsgStatus = 0x1 //indicates message was received by peer
	MSGREAD        MsgStatus = 0x2 //indicates message was read by peer
	MSGAPPROVED    MsgStatus = 0x3 //indicates message was approved (thumb up) by peer
	MSGDISAPPROVED MsgStatus = 0x4 //indicates message was disapproved (thumb down) by peer
)

// DeliveryReceiptMessage represents a delivery receipt as sent e2e encrypted to other threema users when a message has been received
type DeliveryReceiptMessage struct {
	*MessageHeader
	Status    MsgStatus
	MessageID uint64
}

func (msg DeliveryReceiptMessage) MarshalBinary() ([]byte, error) {

	buf := new(bytes.Buffer)
	bufMarshal("msg-type", buf, uint8(MessageTypeDeliveryReceipt))
	bufMarshal("message status", buf, msg.Status)
	bufMarshal("message id", buf, msg.MessageID)
	bufMarshalPadding(buf)

	return buf.Bytes(), nil
}

func (msg *DeliveryReceiptMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var t MsgType
	bufUnmarshal("read message type", buf, &t)
	if t != MessageTypeDeliveryReceipt {
		return errors.New("not correct type")
	}
	stripPadding(buf)
	bufUnmarshal("read message status", buf, &msg.Status)
	bufUnmarshal("read message id", buf, &msg.MessageID)

	return nil
}

func init() {
	messageUnmarshal[MessageTypeDeliveryReceipt] = func(mh *MessageHeader, data []byte) (Message, error) {
		tm := &DeliveryReceiptMessage{
			MessageHeader: mh,
		}
		if err := tm.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return tm, nil
	}
}
