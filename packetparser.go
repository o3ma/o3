// Package o3 functions to convert packets from byte buffers to go structs.
// These functions are called from packethandler only and their
// task is only conversion. Errors are bubbled up the chain as
// panics and will be converted to go errors further up the chain.
package o3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

func parseMsgPkt(buf *bytes.Buffer) (mp messagePacket) {

	mp.PktType = parsePktType(buf)
	mp.Sender = parseIDString(buf)
	mp.Recipient = parseIDString(buf)
	mp.ID = parseUint64(buf)
	mp.Time = parseTime(buf)
	mp.PubNick = parsePubNick(buf)
	mp.Nonce = parseNonce(buf)
	mp.Ciphertext = parseMessage(buf)

	return
}

func parseAckPkt(buf *bytes.Buffer) (ap ackPacket) {

	ap.PktType = parsePktType(buf)
	ap.SenderID = parseIDString(buf)
	ap.MsgID = parseUint64(buf)

	return
}

func parseDeliveryReceipt(buf *bytes.Buffer) deliveryReceiptMessageBody {
	// Strip padding
	// TODO: this should be a helper function
	paddingLen := int(buf.Bytes()[buf.Len()-1])
	buf.Truncate(buf.Len() - paddingLen)

	dm := deliveryReceiptMessageBody{
		status: msgStatus(parseByte(buf)),
		msgID:  parseUint64(buf)}
	return dm
}

func parseConnEstPkt(buf *bytes.Buffer) (cep connEstPacket) {

	cep.PktType = parsePktType(buf)

	return
}

func parseClientHello(buf *bytes.Buffer) (ch clientHelloPacket) {

	ch.ClientSPK = parseKey(buf)
	ch.NoncePrefix = parseNoncePrefix(buf)

	return
}

func parseServerHello(buf *bytes.Buffer) (sh serverHelloPacket) {

	sh.NoncePrefix = parseNoncePrefix(buf)
	sh.Ciphertext = parse64bytes(buf)

	return
}

func parseServerHelloPayload(buf *bytes.Buffer) (serverSPK [32]byte, clientNP [16]byte) {

	serverSPK = parseKey(buf)
	clientNP = parseNoncePrefix(buf)
	return
}

func parseAuthPkt(buf *bytes.Buffer) (ap authPacket) {

	ap.Ciphertext = parse144bytes(buf)
	return
}

func parseUint8(buf *bytes.Buffer) uint8 {
	var ret uint8

	err := binary.Read(buf, binary.LittleEndian, &ret)
	if err != nil {
		panic("uint8")
	}
	return ret
}

func parseUint16(buf *bytes.Buffer) uint16 {
	var ret uint16

	err := binary.Read(buf, binary.LittleEndian, &ret)
	if err != nil {
		panic("uint16")
	}
	return ret
}

func parseUint32(buf *bytes.Buffer) uint32 {
	var ret uint32

	err := binary.Read(buf, binary.LittleEndian, &ret)
	if err != nil {
		panic("uint32")
	}
	return ret
}

func parseInt64(buf *bytes.Buffer) int64 {
	var ret int64

	err := binary.Read(buf, binary.LittleEndian, &ret)
	if err != nil {
		panic("int64")
	}
	return ret
}

func parseUint64(buf *bytes.Buffer) uint64 {
	var ret uint64

	err := binary.Read(buf, binary.LittleEndian, &ret)
	if err != nil {
		panic("uint64")
	}
	return ret
}

func parseMessageType(buf *bytes.Buffer) msgType {
	msgT := parseUint8(buf)
	//TODO check valid range
	return msgType(msgT)
}

func parsePktType(buf *bytes.Buffer) pktType {
	pktT := parseUint32(buf)
	//TODO check valid range
	return pktType(pktT)
}

func parseIDString(buf *bytes.Buffer) IDString {
	var id [8]byte
	err := binary.Read(buf, binary.LittleEndian, &id)
	//TODO check valild characters
	if err != nil {
		panic("Threema ID")
	}
	return IDString(id)
}

func parsePubNick(buf *bytes.Buffer) PubNick {
	var pn PubNick
	err := binary.Read(buf, binary.LittleEndian, &pn)
	//TODO check valild characters
	if err != nil {
		panic("PubNick")
	}
	return pn
}

func parseTime(buf *bytes.Buffer) time.Time {
	return time.Unix(parseInt64(buf), 0)
}

func parseNonce(buf *bytes.Buffer) (n nonce) {
	rawNonce := make([]byte, 24)
	err := binary.Read(buf, binary.LittleEndian, rawNonce)
	if err != nil {
		panic("nonce")
	}
	copy(n.nonce[:], rawNonce)
	return
}

func parseNoncePrefix(buf *bytes.Buffer) (np [16]byte) {
	rawNP := make([]byte, 16)
	err := binary.Read(buf, binary.LittleEndian, rawNP)
	if err != nil {
		panic("nonce prefix")
	}
	copy(np[:], rawNP)
	return
}

func parseMessage(buf *bytes.Buffer) []byte {
	return buf.Bytes()
}

func parseTextMessage(buf *bytes.Buffer) textMessageBody {
	// Strip padding
	// TODO: this should be a helper function
	paddingLen := int(buf.Bytes()[buf.Len()-1])
	buf.Truncate(buf.Len() - paddingLen)

	return textMessageBody{text: string(buf.Bytes())}
}

func parseImageMessage(buf *bytes.Buffer) imageMessageBody {
	// Strip padding
	// TODO: this should be a helper function
	paddingLen := int(buf.Bytes()[buf.Len()-1])
	buf.Truncate(buf.Len() - paddingLen)

	im := imageMessageBody{
		BlobID: parseBlobID(buf),
		Size:   parseUint32(buf),
		Nonce:  parseNonce(buf)}
	im.ServerID = im.BlobID[0]
	return im
}

func parseTypingNotification(buf *bytes.Buffer) (tn typingNotificationBody) {
	tn.OnOff = parseByte(buf)
	return
}

func parseAudioMessage(buf *bytes.Buffer) audioMessageBody {
	// Strip padding
	// TODO: this should be a helper function
	paddingLen := int(buf.Bytes()[buf.Len()-1])
	buf.Truncate(buf.Len() - paddingLen)

	am := audioMessageBody{
		Duration: parseUint16(buf),
		BlobID:   parseBlobID(buf),
		Size:     parseUint32(buf),
		Key:      parseKey(buf)}
	am.ServerID = am.BlobID[0]
	return am
}

func parseGroupImageMessage(buf *bytes.Buffer) groupImageMessageBody {
	// Strip padding
	// TODO: this should be a helper function
	paddingLen := int(buf.Bytes()[buf.Len()-1])
	buf.Truncate(buf.Len() - paddingLen)

	gim := groupImageMessageBody{
		BlobID: parseBlobID(buf),
		Size:   parseUint32(buf),
		Key:    parseKey(buf)}
	gim.ServerID = gim.BlobID[0]
	return gim
}

func parseGroupMessageHeader(buf *bytes.Buffer) groupMessageHeader {
	return groupMessageHeader{
		creatorID: parseIDString(buf),
		groupID:   parseGroupID(buf),
	}
}

func parseGroupManageSetNameMessage(buf *bytes.Buffer) groupManageSetNameMessageBody {
	// Strip padding
	// TODO: this should be a helper function
	paddingLen := int(buf.Bytes()[buf.Len()-1])
	buf.Truncate(buf.Len() - paddingLen)

	return groupManageSetNameMessageBody{groupName: string(buf.Bytes())}
}

func parseGroupManageSetMembersMessage(buf *bytes.Buffer) groupManageSetMembersMessageBody {
	// Strip padding
	// TODO: this should be a helper function
	paddingLen := int(buf.Bytes()[buf.Len()-1])
	buf.Truncate(buf.Len() - paddingLen)

	if (buf.Len() % 8) != 0 {
		panic("List of group members corrupt. Length is no multiple of 8.")
	}

	memberCount := buf.Len() / 8
	gmm := groupManageSetMembersMessageBody{
		groupMembers: make([]IDString, memberCount)}

	for i := 0; i < memberCount; i++ {
		gmm.groupMembers[i] = parseIDString(buf)
	}

	return gmm
}

func parseGroupManageMessageHeader(buf *bytes.Buffer) groupManageMessageHeader {
	return groupManageMessageHeader{
		groupID: parseGroupID(buf),
	}
}

func parseKey(buf *bytes.Buffer) (key [32]byte) {
	rawKey := make([]byte, 32)
	n, err := buf.Read(rawKey)
	if n != 32 || err != nil {
		panic("32-byte key")
	}
	copy(key[:], rawKey)
	return
}

func parseBlobID(buf *bytes.Buffer) (bytes [16]byte) {
	bytebuf := parsenbytes(buf, 16)
	copy(bytes[:], bytebuf)
	return
}

func parseGroupID(buf *bytes.Buffer) (bytes [8]byte) {
	bytebuf := parsenbytes(buf, 8)
	copy(bytes[:], bytebuf)
	return
}

func parse64bytes(buf *bytes.Buffer) (bytes [64]byte) {
	bytebuf := parsenbytes(buf, 64)
	copy(bytes[:], bytebuf)
	return
}

func parse144bytes(buf *bytes.Buffer) (bytes [144]byte) {
	bytebuf := parsenbytes(buf, 144)
	copy(bytes[:], bytebuf)
	return
}

func parseByte(buf *bytes.Buffer) byte {
	b, err := buf.ReadByte()
	if err != nil {
		panic(err)
	}
	return b
}

//helper function: not to be called directly
func parsenbytes(buf *bytes.Buffer, size int) []byte {
	bytes := make([]byte, size)
	n, err := buf.Read(bytes)
	if n != size || err != nil {
		panic(fmt.Sprintf("%d bytes of data", size))
	}
	return bytes
}
