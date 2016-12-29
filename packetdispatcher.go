/*
 * Functions to prepare and send packets. All preparation required to transmit a
 * packet takes place in the packet's respective dispatcher function. Functions
 * from packetserializer are used to convert from struct to byte buffer form that
 * can then be transmitted on the wire. Errors from packetserializer bubble up here
 * in the form of panics that have to be passed on to communicationhandler for
 * conversion to go errors.
 */
package o3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

func dispatcherPanicHandler(context string, i interface{}) error {
	if _, ok := i.(string); ok {
		return fmt.Errorf("%s: error occured dispatching %s", context, i)
	}
	return fmt.Errorf("%s: unknown dispatch error occured: %#v", context, i)
}

func writeHelper(wr io.Writer, buf *bytes.Buffer) {
	i, err := wr.Write(buf.Bytes())
	if i != buf.Len() {
		panic("not enough bytes were transmitted")
	}
	if err != nil {
		panic(err)
	}
}

func (sc *SessionContext) dispatchClientHello(wr io.Writer) {
	defer func() {
		if r := recover(); r != nil {
			panic(dispatcherPanicHandler("client hello", r))
		}
	}()
	var ch clientHelloPacket

	ch.ClientSPK = sc.clientSPK
	ch.NoncePrefix = sc.clientNonce.prefix()

	buf := serializeClientHelloPkt(ch)
	writeHelper(wr, buf)
}

//not necessary on the client side
func (sc *SessionContext) dispatchServerHello(wr io.Writer) {}

func (sc *SessionContext) dispatchAuthMsg(wr io.Writer) {
	defer func() {
		if r := recover(); r != nil {
			panic(dispatcherPanicHandler("authentication packet", r))
		}
	}()
	var app authPacketPayload
	var ap authPacket

	app.Username = sc.ID.ID
	//TODO System Data: app.SysData = ..
	app.ServerNoncePrefix = sc.serverNonce.prefix()
	app.RandomNonce = newNonce()

	//create payload ciphertext
	ct := box.Seal(nil, sc.clientSPK[:], app.RandomNonce.bytes(), &sc.serverLPK, &sc.ID.LSK)
	if len(ct) != 48 {
		panic("error encrypting client short-term public key")
	}
	copy(app.Ciphertext[:], ct[0:48])

	appBuf := serializeAuthPktPayload(app)

	//create auth packet ciphertext
	sc.clientNonce.setCounter(1)
	apct := box.Seal(nil, appBuf.Bytes(), sc.clientNonce.bytes(), &sc.serverSPK, &sc.clientSSK)
	if len(apct) != 144 {
		panic("error encrypting payload")
	}
	copy(ap.Ciphertext[:], apct[0:144])

	buf := serializeAuthPkt(ap)
	writeHelper(wr, buf)
}

func (sc *SessionContext) dispatchAckMsg(wr io.Writer, mp messagePacket) {
	ackP := ackPacket{
		PktType:  CLIENTACK,
		SenderID: mp.Sender,
		MsgID:    mp.ID}
	serializedAckPkt := serializeAckPkt(ackP)

	sc.clientNonce.increaseCounter()
	ackpCipherText := box.Seal(nil, serializedAckPkt.Bytes(), sc.clientNonce.bytes(), &sc.serverSPK, &sc.clientSSK)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(len(ackpCipherText)))
	binary.Write(buf, binary.LittleEndian, ackpCipherText)

	writeHelper(wr, buf)
}

func (sc *SessionContext) dispatchMessage(wr io.Writer, m Message) {
	mh := m.header()

	randNonce := newRandomNonce()

	recipientID, ok := sc.ID.Contacts.Get(mh.recipient.String())
	if !ok {
		panic("Recipient not found in contacts!")
	}
	msgCipherText := box.Seal(nil, m.Serialize(), randNonce.bytes(), &recipientID.LPK, &sc.ID.LSK)

	messagePkt := messagePacket{
		PktType:    SENDINGMSG,
		Sender:     mh.sender,
		Recipient:  mh.recipient,
		ID:         mh.id,
		Time:       mh.time,
		Flags:      msgFlags{PushMessage: true},
		PubNick:    mh.pubNick,
		Nonce:      randNonce,
		Ciphertext: msgCipherText,
	}

	serializedMsgPkt := serializeMsgPkt(messagePkt)

	sc.clientNonce.increaseCounter()
	serializedMsgPktCipherText := box.Seal(nil, serializedMsgPkt.Bytes(), sc.clientNonce.bytes(), &sc.serverSPK, &sc.clientSSK)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(len(serializedMsgPktCipherText)))
	binary.Write(buf, binary.LittleEndian, serializedMsgPktCipherText)

	writeHelper(wr, buf)
}
