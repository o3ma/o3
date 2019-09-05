//
// Package o3 functions to prepare and send packets. All preparation required to transmit a
// packet takes place in the packet's respective dispatcher function. Functions
// from packetserializer are used to convert from struct to byte buffer form that
// can then be transmitted on the wire. Errors from packetserializer bubble up here
// in the form of panics that have to be passed on to communicationhandler for
// conversion to go errors.
//
package o3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/nacl/box"
)

func dispatcherPanicHandler(context string, i interface{}) error {
	if _, ok := i.(string); ok {
		return fmt.Errorf("%s: error occurred dispatching %s", context, i)
	}
	return fmt.Errorf("%s: unknown dispatch error occurred: %#v", context, i)
}

func writeHelper(wr io.Writer, data []byte) {
	i, err := wr.Write(data)
	if i != len(data) {
		panic("not enough bytes were transmitted")
	}
	if err != nil {
		panic(err)
	}
}

func writeBufferHelper(wr io.Writer, buf *bytes.Buffer) {
	writeHelper(wr, buf.Bytes())
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

	buf, _ := ch.MarshalBinary()
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

	appBuf, _ := app.MarshalBinary()

	//create auth packet ciphertext
	sc.clientNonce.setCounter(1)
	apct := box.Seal(nil, appBuf, sc.clientNonce.bytes(), &sc.serverSPK, &sc.clientSSK)
	if len(apct) != 144 {
		panic("error encrypting payload")
	}
	copy(ap.Ciphertext[:], apct[0:144])

	buf, _ := ap.MarshalBinary()
	writeHelper(wr, buf)
}

func (sc *SessionContext) dispatchAckMsg(wr io.Writer, mp messagePacket) {
	ackP := ackPacket{
		PktType:  clientAck,
		SenderID: mp.Sender,
		MsgID:    mp.ID,
	}
	serializedAckPkt, _ := ackP.MarshalBinary()

	sc.clientNonce.increaseCounter()
	ackpCipherText := box.Seal(nil, serializedAckPkt, sc.clientNonce.bytes(), &sc.serverSPK, &sc.clientSSK)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(len(ackpCipherText)))
	binary.Write(buf, binary.LittleEndian, ackpCipherText)

	writeBufferHelper(wr, buf)
}

func (sc *SessionContext) dispatchEchoMsg(wr io.Writer, oldEchoPacket echoPacket) {
	ep := echoPacket{Counter: oldEchoPacket.Counter + 1}
	serializedEchoPkt, _ := ep.MarshalBinary()

	sc.clientNonce.increaseCounter()
	epCipherText := box.Seal(nil, serializedEchoPkt, sc.clientNonce.bytes(), &sc.serverSPK, &sc.clientSSK)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(len(epCipherText)))
	binary.Write(buf, binary.LittleEndian, epCipherText)

	writeBufferHelper(wr, buf)
}

func (sc *SessionContext) dispatchMessage(wr io.Writer, m Message) {
	mh := m.Header()
	randNonce := newRandomNonce()

	recipient, ok := sc.ID.Contacts.Get(mh.Recipient.String())
	if !ok {
		var tr ThreemaRest
		var err error

		recipient, err = tr.GetContactByID(mh.Recipient)
		if err != nil {
			panic("Recipient's PublicKey could not be found!")
		}
		sc.ID.Contacts.Add(recipient)
	}
	data, _ := m.MarshalBinary()
	msgCipherText := box.Seal(nil, data, randNonce.bytes(), &recipient.LPK, &sc.ID.LSK)

	messagePkt := messagePacket{
		Sender:     mh.Sender,
		Recipient:  mh.Recipient,
		ID:         mh.ID,
		Time:       mh.Time,
		PubNick:    mh.PubNick,
		PktType:    sendingMsg,
		Flags:      msgFlags{PushMessage: true},
		Nonce:      randNonce,
		Ciphertext: msgCipherText,
	}
	if messagePkt.Time.IsZero() {
		messagePkt.Time = time.Now()
	}
	serializedMsgPkt, _ := messagePkt.MarshalBinary()

	sc.clientNonce.increaseCounter()
	serializedMsgPktCipherText := box.Seal(nil, serializedMsgPkt, sc.clientNonce.bytes(), &sc.serverSPK, &sc.clientSSK)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(len(serializedMsgPktCipherText)))
	binary.Write(buf, binary.LittleEndian, serializedMsgPktCipherText)

	writeBufferHelper(wr, buf)
}
