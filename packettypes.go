package o3

import (
	"bytes"
	"encoding"
	"fmt"
	"time"
)

type pktType uint32

const (
	// sendingMsg is the packet type of a message packet from client to server
	sendingMsg pktType = 0x1
	// deliveringMsg is the packet type of a message packet from server to client
	deliveringMsg pktType = 0x2
	// echoMsg is the packet type of a echo reply
	echoMsg pktType = 0x80
	// serverAck is the packet type of a server ack for a message sent by the client
	serverAck pktType = 0x81
	// clientAck is the packet type of a client ack for a message delivered by the server
	clientAck pktType = 0x82
	// connEstablished is the packet type of a pkt send by the server when all MSGs have been delivered
	connEstablished pktType = 0xd0
	// duplicateConnectionError is sent whenever the connection is ursurped by another client
	duplicateConnectionError pktType = 0xE0
	// msgHeaderLength is the length of a ThreemaMessageHeader
	msgHeaderLength uint8 = 64
)

// ThreemaMessageHeader contains fields that every type of message needs
type messagePacket struct {
	encoding.BinaryMarshaler

	PktType    pktType
	Sender     IDString
	Recipient  IDString
	ID         uint64
	Time       time.Time
	Flags      msgFlags
	PubNick    PubNick
	Nonce      nonce
	Ciphertext []byte
	Plaintext  []byte
}

func (mp *messagePacket) Header() MessageHeader {
	return MessageHeader{
		Sender:    mp.Sender,
		Recipient: mp.Recipient,
		ID:        mp.ID,
		Time:      mp.Time,
		PubNick:   mp.PubNick,
	}
}

func (mp *messagePacket) GetMessageType() (mt MsgType) {
	buf := bytes.NewBuffer(mp.Plaintext)
	bufUnmarshal("msg-type", buf, &mt)
	return
}

func (mp *messagePacket) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	bufMarshal("pkg-type", buf, mp.PktType)
	bufMarshal("sender", buf, mp.Sender)
	bufMarshal("recipient", buf, mp.Recipient)
	bufMarshal("id", buf, mp.ID)
	bufMarshal("time", buf, uint32(mp.Time.Unix()))
	flags, _ := mp.Flags.MarshalBinary()
	bufMarshal("flags", buf, flags)
	// The three following bytes are unused
	bufMarshal("unused", buf, []byte{0x00, 0x00, 0x00})
	bufMarshal("public nick", buf, mp.PubNick)
	bufMarshal("nonce", buf, mp.Nonce.nonce)
	bufMarshal("ciphertext", buf, mp.Ciphertext)

	return buf.Bytes(), nil
}

func (mp *messagePacket) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	bufUnmarshal("pkg-type", buf, &mp.PktType)
	bufUnmarshal("sender", buf, &mp.Sender)
	bufUnmarshal("recipient", buf, &mp.Recipient)
	bufUnmarshal("id", buf, &mp.ID)

	var t int32
	bufUnmarshal("time", buf, &t)
	mp.Time = time.Unix(int64(t), 0)

	// 1 byte for flags + 3 bytes unused
	unused := make([]byte, 4)
	bufUnmarshal("unused", buf, &unused)

	bufUnmarshal("public nick", buf, &mp.PubNick)
	bufUnmarshal("nonce", buf, &mp.Nonce.nonce)
	mp.Ciphertext = buf.Bytes()

	return nil
}
func (mp *messagePacket) String() string {
	return fmt.Sprintf(
		`type: %v
sender:%s
recipient:%s
public nick:%s`,
		mp.PktType,
		mp.Sender,
		mp.Recipient,
		mp.PubNick)
}

type ackPacket struct {
	PktType  pktType
	SenderID IDString
	MsgID    uint64
}

func (ap *ackPacket) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	bufMarshal("pkg-type", buf, ap.PktType)
	bufMarshal("sender", buf, ap.SenderID)
	bufMarshal("msg id", buf, ap.MsgID)

	return buf.Bytes(), nil
}

func (ap *ackPacket) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	bufUnmarshal("pkg-type", buf, &ap.PktType)
	bufUnmarshal("sender", buf, &ap.SenderID)
	bufUnmarshal("msg id", buf, &ap.MsgID)

	return nil
}

type echoPacket struct {
	PktType pktType
	Counter uint64
}

func (ep *echoPacket) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	bufMarshal("pkg type", buf, ep.PktType)
	bufMarshal("counter", buf, ep.Counter)

	return buf.Bytes(), nil
}

func (ep *echoPacket) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	bufUnmarshal("pkg type", buf, &ep.PktType)
	bufUnmarshal("counter", buf, &ep.Counter)

	return nil
}

type connEstPacket struct {
	PktType pktType
}

func (pkg *connEstPacket) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	bufUnmarshal("pkg type", buf, &pkg.PktType)
	return nil
}

type clientHelloPacket struct {
	ClientSPK   [32]byte
	NoncePrefix [16]byte
}

func (ch clientHelloPacket) MarshalBinary() ([]byte, error) {

	buf := new(bytes.Buffer)

	bufMarshal("client spk", buf, ch.ClientSPK)
	bufMarshal("nonce prefix", buf, ch.NoncePrefix)

	return buf.Bytes(), nil
}

type serverHelloPacket struct {
	NoncePrefix [16]byte
	Ciphertext  [64]byte
}

func (sh serverHelloPacket) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	//TODO finish
	return buf.Bytes(), nil
}

func (sh *serverHelloPacket) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	bytebuf := bufUnmarshalBytes(buf, 16)
	copy(sh.NoncePrefix[:], bytebuf)

	bytebuf = bufUnmarshalBytes(buf, 64)
	copy(sh.Ciphertext[:], bytebuf)

	return nil
}

type authPacket struct {
	Ciphertext [144]byte
}

func (ap *authPacket) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	bufMarshal("ciphertext", buf, ap.Ciphertext)
	return buf.Bytes(), nil
}

//plain content of an auth packet
type authPacketPayload struct {
	Username          IDString
	SysData           [32]byte
	ServerNoncePrefix [16]byte
	RandomNonce       nonce
	Ciphertext        [48]byte
}

func (app *authPacketPayload) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	bufMarshal("username", buf, app.Username)
	bufMarshal("sys-data", buf, app.SysData)
	bufMarshal("server nonce prefix", buf, app.ServerNoncePrefix)
	bufMarshal("random nonce", buf, app.RandomNonce)
	bufMarshal("ciphertext", buf, app.Ciphertext)

	return buf.Bytes(), nil
}
