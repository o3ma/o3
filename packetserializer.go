/*Functions to covert packets from go structs to byte buffers.
 *These functions will only be called from packetdispatcher and
 *their task is only conversion (inversion of the parser).
 *Errors are passed up the chain in the form of panics and will
 *be converted to go errors further up the chain.
 */

package o3

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

func serializeMsgPkt(mp messagePacket) *bytes.Buffer {

	buf := new(bytes.Buffer)
	serializePktType(buf, mp.PktType)
	serializeIDString(buf, mp.Sender)
	serializeIDString(buf, mp.Recipient)
	serializeMsgID(buf, mp.ID)
	serializeTime(buf, mp.Time)
	serializeMsgFlags(buf, mp.Flags)
	// The three following bytes are unused
	serializeUnusedBytes(buf)
	serializePubNick(buf, mp.PubNick)
	serializeNonce(buf, mp.Nonce)
	serializeCiphertext(buf, mp.Ciphertext)

	return buf
}

func serializeTextMsg(tm TextMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)
	serializeMsgType(buf, TEXTMESSAGE)
	serializeText(buf, tm.text)
	serializePadding(buf)

	return buf
}

func serializeImageMsg(im ImageMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)
	serializeMsgType(buf, IMAGEMESSAGE)
	serializeBlobID(buf, im.BlobID)
	serializeUint32(buf, im.Size)
	serializeNonce(buf, im.Nonce)
	serializePadding(buf)
	return buf
}

func serializeAudioMsg(am AudioMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)
	serializeMsgType(buf, AUDIOMESSAGE)
	// AudioClip duration
	serializeUint16(buf, 0xFFFF)
	serializeBlobID(buf, am.BlobID)
	serializeUint32(buf, am.Size)
	serializeKey(buf, am.Key)
	serializePadding(buf)

	return buf
}

func serializeGroupTextMsg(gtm GroupTextMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializeMsgType(buf, GROUPTEXTMESSAGE)
	serializeGroupHeader(buf, gtm.groupMessageHeader)
	serializeText(buf, gtm.text)
	serializePadding(buf)

	return buf
}

func serializeGroupImageMsg(gim GroupImageMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)
	serializeMsgType(buf, GROUPIMAGEMESSAGE)
	serializeGroupHeader(buf, gim.groupMessageHeader)
	serializeBlobID(buf, gim.BlobID)
	serializeUint32(buf, gim.Size)
	serializeKey(buf, gim.Key)
	serializePadding(buf)

	return buf
}

// func serializeGroupAudioMsg(gam GroupAudioMessage) *bytes.Buffer {
// 	defer func() {
// 		if r := recover(); r != nil {
// 			panic(serializerPanicHandler("AudioMsg", r))
// 		}
// 	}()
// 	buf := new(bytes.Buffer)

// 	serializeMsgType(buf, AUDIOMESSAGE)

// 	// AudioClip duration, fixed value for now
// 	serializeUint16(buf, 0x0000)

// 	serializeBlobID(buf, gam.BlobID)
// 	serializeUint32(buf, gam.Size)
// 	serializeKey(buf, gam.Key)
// 	serializePadding(buf)
// 	return buf
// }

func serializeGroupMemberLeftMessage(glm GroupMemberLeftMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializeMsgType(buf, GROUPMEMBERLEFTMESSAGE)
	serializeGroupHeader(buf, glm.groupMessageHeader)
	serializePadding(buf)

	return buf
}

func serializeGroupManageSetNameMessage(gmm GroupManageSetNameMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializeMsgType(buf, GROUPSETNAMEMESSAGE)
	serializeGroupID(buf, gmm.GroupID())
	serializeText(buf, gmm.Name())
	serializePadding(buf)

	return buf
}

func serializeGroupManageSetMembersMessage(gmm GroupManageSetMembersMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializeMsgType(buf, GROUPSETMEMEBERSMESSAGE)
	serializeGroupID(buf, gmm.GroupID())
	for _, member := range gmm.Members() {
		serializeIDString(buf, member)
	}
	serializePadding(buf)

	return buf
}

func serializeAckPkt(ap ackPacket) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializePktType(buf, ap.PktType)
	serializeIDString(buf, ap.SenderID)
	serializeMsgID(buf, ap.MsgID)

	return buf
}

func serializeEchoPkt(ep echoPacket) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializePktType(buf, ep.PktType)
	serializeUint64(buf, ep.Counter)

	return buf
}

func serializeDeliveryReceiptMsg(dm DeliveryReceiptMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)
	serializeMsgType(buf, DELIVERYRECEIPT)
	serializeMsgStatus(buf, dm.status)
	serializeMsgID(buf, dm.msgID)
	serializePadding(buf)

	return buf
}

func serializeClientHelloPkt(ch clientHelloPacket) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializeKey(buf, ch.ClientSPK)
	serializeNoncePrefix(buf, ch.NoncePrefix)

	return buf
}

func serializeServerHelloPkt(sh serverHelloPacket) *bytes.Buffer {

	buf := new(bytes.Buffer)

	//TODO finish

	return buf
}

func serializeAuthPktPayload(app authPacketPayload) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializeIDString(buf, app.Username)
	serializeSysData(buf, app.SysData)
	serializeNoncePrefix(buf, app.ServerNoncePrefix)
	serializeNonce(buf, app.RandomNonce)
	serializeArbitraryData(buf, app.Ciphertext)

	return buf
}

func serializeAuthPkt(ap authPacket) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializeCiphertext(buf, ap.Ciphertext[:])

	return buf
}

func serializeTypingNotification(tn TypingNotificationMessage) *bytes.Buffer {

	buf := new(bytes.Buffer)

	serializeByte(buf, tn.OnOff)

	return buf
}

func serializerPanicHandler(context string, i interface{}) error {
	if _, ok := i.(string); ok {
		return fmt.Errorf("%s: error occurred serializing %s", context, i)
	}
	return fmt.Errorf("%s: unknown serializing error occurred: %#v", context, i)
}

func serializeHelper(buf *bytes.Buffer, i interface{}) *bytes.Buffer {
	return contextualSerializeHelper(fmt.Sprintf("%T", i), buf, i)
}

func contextualSerializeHelper(context string, buf *bytes.Buffer, i interface{}) *bytes.Buffer {
	err := binary.Write(buf, binary.LittleEndian, i)
	if err != nil {
		panic(context)
	}
	return buf
}

// serializePadding returns a byte slice filled with n repetitions of the byte value n
func serializePadding(buf *bytes.Buffer) {
	paddingValueBig, err := rand.Int(rand.Reader, big.NewInt(255))
	if err != nil {
		panic(err)
	}
	paddingValue := byte(paddingValueBig.Int64())
	padding := make([]byte, paddingValue)
	for i := range padding {
		padding[i] = paddingValue
	}
	serializeHelper(buf, padding)
}

// TODO: clean this up!
func serializeUint8(num uint8, buf *bytes.Buffer) *bytes.Buffer {
	return serializeHelper(buf, num)
}

func serializeUint16(buf *bytes.Buffer, num uint16) *bytes.Buffer {
	return serializeHelper(buf, num)
}

func serializeUint32(buf *bytes.Buffer, num uint32) *bytes.Buffer {
	return serializeHelper(buf, num)
}

func serializeInt64(buf *bytes.Buffer, num int64) *bytes.Buffer {
	return serializeHelper(buf, num)
}

func serializeUint64(buf *bytes.Buffer, num uint64) *bytes.Buffer {
	return serializeHelper(buf, num)
}

func serializePktType(buf *bytes.Buffer, pktT pktType) *bytes.Buffer {
	return serializeUint32(buf, uint32(pktT))
}

func serializeMsgType(buf *bytes.Buffer, msgT MsgType) *bytes.Buffer {
	return serializeUint8(uint8(msgT), buf)
}

func serializeByte(buf *bytes.Buffer, b byte) *bytes.Buffer {
	err := buf.WriteByte(b)
	if err != nil {
		panic(err)
	}
	return buf
}

func serializeMsgFlags(buf *bytes.Buffer, flags msgFlags) *bytes.Buffer {
	var flagsByte byte
	if flags.PushMessage {
		flagsByte |= (1 << 0)
	}
	if flags.NoQueuing {
		flagsByte |= (1 << 1)
	}
	if flags.NoAckExpected {
		flagsByte |= (1 << 2)
	}
	if flags.MessageHasAlreadyBeenDelivered {
		flagsByte |= (1 << 3)
	}
	if flags.GroupMessage {
		flagsByte |= (1 << 4)
	}
	serializeUint8(flagsByte, buf)
	return buf
}

func serializeUnusedBytes(buf *bytes.Buffer) *bytes.Buffer {
	return serializeArbitraryData(buf, []byte{0x00, 0x00, 0x00})
}

func serializeKey(buf *bytes.Buffer, key [32]byte) *bytes.Buffer {
	return contextualSerializeHelper("key", buf, key)
}

func serializeNoncePrefix(buf *bytes.Buffer, np [16]byte) *bytes.Buffer {
	return contextualSerializeHelper("nonce prefix", buf, np)
}

func serializeIDString(buf *bytes.Buffer, is IDString) *bytes.Buffer {
	return contextualSerializeHelper("id string", buf, is)
}

func serializePubNick(buf *bytes.Buffer, pn PubNick) *bytes.Buffer {
	return contextualSerializeHelper("public nickname", buf, pn)
}

func serializeMsgStatus(buf *bytes.Buffer, msgStatus MsgStatus) *bytes.Buffer {
	return serializeByte(buf, byte(msgStatus))
}

func serializeMsgID(buf *bytes.Buffer, id uint64) *bytes.Buffer {
	return serializeUint64(buf, id)
}

func serializeTime(buf *bytes.Buffer, t time.Time) *bytes.Buffer {
	//TODO time sanity checks
	return contextualSerializeHelper("time", buf, uint32(t.Unix()))
}

func serializeNonce(buf *bytes.Buffer, n nonce) *bytes.Buffer {
	return contextualSerializeHelper("nonce", buf, n.nonce)
}

func serializeCiphertext(buf *bytes.Buffer, bts []byte) *bytes.Buffer {
	//TODO error handling written bytes vs. len(bts)?
	return contextualSerializeHelper("ciphertext", buf, bts)
}

func serializeSysData(buf *bytes.Buffer, sysData [32]byte) *bytes.Buffer {
	return contextualSerializeHelper("system data", buf, sysData)
}

func serializeText(buf *bytes.Buffer, text string) *bytes.Buffer {
	// TODO: sanatize?
	return serializeHelper(buf, []byte(text))
}

func serializeBlobID(buf *bytes.Buffer, blobID [16]byte) *bytes.Buffer {
	return serializeHelper(buf, []byte(blobID[:]))
}

func serializeArbitraryData(buf *bytes.Buffer, i interface{}) *bytes.Buffer {
	//TODO type assertions for error handling?
	//TODO what to do about context?
	return serializeHelper(buf, i)
}

func serializeGroupID(buf *bytes.Buffer, groupID [8]byte) *bytes.Buffer {
	return serializeHelper(buf, []byte(groupID[:]))
}

func serializeGroupHeader(buf *bytes.Buffer, gh groupMessageHeader) *bytes.Buffer {
	serializeIDString(buf, gh.creatorID)
	serializeGroupID(buf, gh.groupID)
	return buf
}
