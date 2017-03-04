package o3

import "time"

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
	// douplicateConnectionError is sent whenever the connection is ursurped by another client
	douplicateConnectionError pktType = 0xE0
	// msgHeaderLength is the length of a ThreemaMessageHeader
	msgHeaderLength uint8 = 64
)

// ThreemaMessageHeader contains fields that every type of message needs
type messagePacket struct {
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

type ackPacket struct {
	PktType  pktType
	SenderID IDString
	MsgID    uint64
}

type echoPacket struct {
	PktType pktType
	Counter uint64
}

type connEstPacket struct {
	PktType pktType
}

type clientHelloPacket struct {
	ClientSPK   [32]byte
	NoncePrefix [16]byte
}

type serverHelloPacket struct {
	NoncePrefix [16]byte
	Ciphertext  [64]byte
}

type authPacket struct {
	Ciphertext [144]byte
}

//plain content of an auth packet
type authPacketPayload struct {
	Username          IDString
	SysData           [32]byte
	ServerNoncePrefix [16]byte
	RandomNonce       nonce
	Ciphertext        [48]byte
}
