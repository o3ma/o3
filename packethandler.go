// Package o3 handler functions for individual incoming packets. All functions here are called from
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

	"golang.org/x/crypto/nacl/box"
)

func handlerPanicHandler(context string, i interface{}) error {
	if err, ok := i.(error); ok {
		return fmt.Errorf("%s: handling error occurred: %s", context, err.Error())
	}
	if _, ok := i.(string); ok {
		return fmt.Errorf("%s: error occurred handling %s", context, i)
	}
	return fmt.Errorf("%s: unknown handling error occurred: %#v", context, i)
}

//not needed at the client
func (sc *SessionContext) handleClientHello(buf *bytes.Buffer) {}

func (sc *SessionContext) handleServerHello(buf *bytes.Buffer) {
	defer func() {
		if r := recover(); r != nil {
			panic(handlerPanicHandler("server hello", r))
		}
	}()
	sh := serverHelloPacket{}
	sh.UnmarshalBinary(buf.Bytes())

	sc.serverNonce.initialize(sh.NoncePrefix, 1)

	plaintext, ok := box.Open(nil, sh.Ciphertext[:], sc.serverNonce.bytes(), &sc.serverLPK, &sc.clientSSK)
	if !ok {
		panic(handlerPanicHandler("handleServerHello", "decrypting cyphertext"))
	}

	rdr := bytes.NewBuffer(plaintext)
	var serverSPK [32]byte
	var clientNP [16]byte
	bufUnmarshal("server spk", rdr, &serverSPK)
	bufUnmarshal("client np", rdr, &clientNP)

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
			panic(handlerPanicHandler("handleClientServerMsg", r))
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
	case deliveringMsg:
		// It is an e2e message!
		msgPkt := messagePacket{}
		msgPkt.UnmarshalBinary(plaintext)
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
			sc.ID.Contacts.Add(sender)
		}
		// Decrypt using our private and their public key
		msgPkt.Plaintext, ok = box.Open(nil, msgPkt.Ciphertext, msgPkt.Nonce.bytes(), &sender.LPK, &sc.ID.LSK)
		if !ok {
			panic("Cannot decrypt e2e MSG!")
		}

		return msgPkt
	case serverAck:
		// It is an ACK for a message we sent
		pkg := ackPacket{}
		pkg.UnmarshalBinary(plaintext)
		return pkg
	case echoMsg:
		// It is an echo reply
		pkg := echoPacket{}
		pkg.UnmarshalBinary(plaintext)
		return pkg
	case connEstablished:
		// We have received all enqueued messages
		pkg := connEstPacket{}
		pkg.UnmarshalBinary(plaintext)
		return pkg
	case duplicateConnectionError:
		return errDuplicateConn
	default:
		fmt.Printf("Unknown PktType: %.2x", plaintext)
		return nil
	}
}

//handleMessagePacket parses a messagePacket and returns the according Message type (ImageMessage, TextMessage etc.)
func (sc *SessionContext) handleMessagePacket(mp messagePacket) (Message, error) {
	// DEBUG
	//fmt.Print(hex.Dump(mp.Plaintext))

	mt := mp.GetMessageType()

	if msgGen, ok := messageUnmarshal[mt]; ok {
		mh := mp.header()
		msg, err := msgGen(&mh, mp.Plaintext)

		return msg, err
	}
	fmt.Printf("\n%2x\n", mp.Plaintext)
	fmt.Printf("\n%s\n", mp.Plaintext)
	return nil, fmt.Errorf("o3: unknown MessageType: %d", mt)
}
