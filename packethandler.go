// Package o3 handler functions for invididual incoming packets. All functions here are called from
// communicationhandler. Functions in here use packetparser to parse packets into their
// respective structs. Any action required upon receiving a specific packet is then per-
// formed within its handler like updating nonces and storing keys in the session context.
// Errors in underlying functions bubble up to here in the form of panics and are passed
// on to communicationhandler for central conversion to go errors.
package o3

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"encoding/hex"

	"golang.org/x/crypto/nacl/box"
)

func handlerPanicHandler(context string, i interface{}) error {
	if _, ok := i.(string); ok {
		return fmt.Errorf("%s: error occured handling %s", context, i)
	}
	return fmt.Errorf("%s: unknown handling error occured: %#v", context, i)
}

//not needed at the client
func (sc *SessionContext) handleClientHello(buf *bytes.Buffer) {}

func (sc *SessionContext) handleServerHello(buf *bytes.Buffer) {
	defer func() {
		if r := recover(); r != nil {
			panic(handlerPanicHandler("server hello", r))
		}
	}()
	sh := parseServerHello(buf)

	sc.serverNonce.initialize(sh.NoncePrefix, 1)

	plaintext, ok := box.Open(nil, sh.Ciphertext[:], sc.serverNonce.bytes(), &sc.serverLPK, &sc.clientSSK)
	if !ok {
		panic(handlerPanicHandler("handleServerHello", "decrypting cyphertext"))
	}

	rdr := bytes.NewBuffer(plaintext)
	serverSPK, clientNP := parseServerHelloPayload(rdr)

	sc.serverSPK = serverSPK
	if clientNP != sc.clientNonce.prefix() {
		panic("client nonce check failed")
	}

}

func (sc *SessionContext) handleHandshakeAck(buf *bytes.Buffer) {
	defer func() {
		if r := recover(); r != nil {
			panic(handlerPanicHandler("handshake acknowledgement", r))
		}
	}()
	sc.serverNonce.setCounter(2)
	_, ok := box.Open(nil, buf.Bytes(), sc.serverNonce.bytes(), &sc.serverSPK, &sc.clientSSK)
	if !ok {
		panic("error decrypting payload")
	}
	//TODO check zero content?
}

func (sc *SessionContext) handleAuthResponse(buf *bytes.Buffer) {}

func (sc *SessionContext) handleAckMsg(buf *bytes.Buffer) {}

// handleDataMsg
func (sc *SessionContext) handleClientServerMsg(buf *bytes.Buffer) interface{} {
	defer func() {
		if r := recover(); r != nil {
			panic(handlerPanicHandler("handleDataMsg", r))
		}
	}()

	sc.serverNonce.increaseCounter()
	plaintext, ok := box.Open(nil, buf.Bytes(), sc.serverNonce.bytes(), &sc.serverSPK, &sc.clientSSK)
	if !ok {
		panic("Cannot decrypt received packet")
	}

	var pt pktType

	//TODO this can be done nicer
	binary.Read(bytes.NewReader(plaintext[:4]), binary.LittleEndian, &pt)

	switch pt {
	case DELIVERINGMSG:
		// It is an e2e message!
		msgPkt := parseMsgPkt(bytes.NewBuffer(plaintext))
		// Find the sender in our contacts, because we need their public key
		sender, ok := sc.ID.Contacts.Get(msgPkt.Sender.String())
		if !ok {
			var tr ThreemaRest
			var err error
			// TODO: Add to local contacts?
			sender, err = tr.GetContactByID(msgPkt.Sender)
			if err != nil {
				panic("Sender's PublicKey could not be found!")
			}
		}
		// Decrypt using our private and their public key
		msgPkt.Plaintext, ok = box.Open(nil, msgPkt.Ciphertext, msgPkt.Nonce.bytes(), &sender.LPK, &sc.ID.LSK)
		if !ok {
			panic("Cannot decrypt e2e MSG!")
		}

		return msgPkt
	case CLIENTACK:
		// It is an ACK for a message we sent
		return parseAckPkt(bytes.NewBuffer(plaintext))
	case CONNESTABLISHED:
		// We have received all enqueued messages
		return parseConnEstPkt(bytes.NewBuffer(plaintext))

	}
	return nil
}

//handleMessagePacket parses a messagePacket and returns the according Message type (ImageMessage, TextMessage etc.)
func (sc *SessionContext) handleMessagePacket(mp messagePacket) (Message, error) {
	// DEBUG
	//fmt.Print(hex.Dump(mp.Plaintext))

	buf := bytes.NewBuffer(mp.Plaintext)

	var message Message
	mt := parseMessageType(buf)
	switch mt {
	case TEXTMESSAGE:
		message = TextMessage{
			messageHeader:   newMsgHdrFromPkt(mp),
			textMessageBody: parseTextMessage(buf)}
	case IMAGEMESSAGE:
		message = ImageMessage{
			messageHeader:    newMsgHdrFromPkt(mp),
			imageMessageBody: parseImageMessage(buf)}
	case AUDIOMESSAGE:
		message = AudioMessage{
			messageHeader:    newMsgHdrFromPkt(mp),
			audioMessageBody: parseAudioMessage(buf)}
	case GROUPTEXTMESSAGE:
		message = GroupTextMessage{
			groupMessageHeader: parseGroupMessageHeader(buf),
			TextMessage: TextMessage{
				messageHeader:   newMsgHdrFromPkt(mp),
				textMessageBody: parseTextMessage(buf)}}
	case GROUPIMAGEMESSAGE:
		message = GroupImageMessage{
			groupMessageHeader:    parseGroupMessageHeader(buf),
			messageHeader:         newMsgHdrFromPkt(mp),
			groupImageMessageBody: parseGroupImageMessage(buf)}
	case GROUPSETNAMEMESSAGE:
		message = GroupManageSetNameMessage{
			groupManageMessageHeader:      parseGroupManageMessageHeader(buf),
			messageHeader:                 newMsgHdrFromPkt(mp),
			groupManageSetNameMessageBody: parseGroupManageSetNameMessage(buf)}
	case GROUPSETMEMEBERSMESSAGE:
		message = GroupManageSetMembersMessage{
			groupManageMessageHeader:         parseGroupManageMessageHeader(buf),
			messageHeader:                    newMsgHdrFromPkt(mp),
			groupManageSetMembersMessageBody: parseGroupManageSetMembersMessage(buf)}
	case GROUPMEMBERLEFTMESSAGE:
		fmt.Println(hex.Dump(buf.Bytes()))
		message = GroupMemberLeftMessage{
			messageHeader:      newMsgHdrFromPkt(mp),
			groupMessageHeader: parseGroupMessageHeader(buf)}
	case DELIVERYRECEIPT:
		message = DeliveryReceiptMessage{
			messageHeader:              newMsgHdrFromPkt(mp),
			deliveryReceiptMessageBody: parseDeliveryReceipt(buf)}
	case TYPINGNOTIFICATION:
		message = TypingNotificationMessage{
			messageHeader:          newMsgHdrFromPkt(mp),
			typingNotificationBody: parseTypingNotification(buf)}
	default:
		fmt.Printf("\n%2x\n", buf)
		fmt.Printf("\n%s\n", buf)
		return nil, fmt.Errorf("o3: unknown MessageType: %d", mt)
	}
	return message, nil
}

func newMsgHdrFromPkt(mp messagePacket) messageHeader {
	return messageHeader{
		sender:    mp.Sender,
		recipient: mp.Recipient,
		id:        mp.ID,
		time:      mp.Time,
		pubNick:   mp.PubNick}
}
