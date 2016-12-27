/*
 * Central communication unit responsible for complete exchanges (like handshake and subsequent
 * message reception). Uses functions in packethandler and packetdispatcher to deal with incoming
 * and outgoing messages. Errors in underlying functions bubble up as panics and have to be re-
 * covered here, converted to go errors and returned.
 */

package o3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func receiveHelper(reader io.Reader, n int) *bytes.Buffer {

	buf := make([]byte, n)
	//TODO handle number of received bytes?
	_, err := reader.Read(buf)
	if err != nil {
		panic(err)
	}
	return bytes.NewBuffer(buf)
}

// ReceivedMsg is a type used to transmit messages via a channel
type ReceivedMsg struct {
	Msg Message
	Err error
}

// ReceiveMessages receives all enqueued Messages and writes the results
// to the channel passed as argument
func (sc *SessionContext) ReceiveMessages() (<-chan ReceivedMsg, error) {
	defer func() {
		if r := recover(); r != nil {
			// TODO: Return the error
			handlerPanicHandler("Receive Messages", r)
		}
	}()

	conn, err := net.Dial("tcp", "g-33.0.threema.ch:5222")
	if err != nil {
		return nil, err
	}

	//handshake
	Info.Println("Initiating Handshake")
	sc.dispatchClientHello(conn)
	sc.handleServerHello(receiveHelper(conn, 80))
	sc.dispatchAuthMsg(conn)
	sc.handleHandshakeAck(receiveHelper(conn, 32))
	Info.Println("Handshake Completed")

	//receive messages
	msgchan := make(chan ReceivedMsg)
	go func() {
	recv:
		for {
			pktIntf, err := sc.receivePacket(conn)
			if err != nil {
				if err == io.EOF {
					break recv
				}
				Error.Printf("receivePacket failed: %s", err)
				msgchan <- ReceivedMsg{
					Msg: nil,
					Err: err,
				}
				// TODO: break/return on specific errors - i.e. connection reset
				continue
			}

			switch pkt := pktIntf.(type) {
			case messagePacket:
				// Acknowledge message packet
				sc.dispatchAckMsg(conn, pkt)

				// Get the actual message
				var rmsg ReceivedMsg
				rmsg.Msg, rmsg.Err = sc.handleMessagePacket(pkt)
				msgchan <- rmsg
			case ackPacket:
				fmt.Printf("Got Ack: \n%v\n", pkt)
			case connEstPacket:
				Info.Printf("Got Message: %#v\n", pkt)
			default:
				Warning.Printf("ReceiveMessages: unhandled packet type: %T", pkt)
				return
			}
			// TODO: Implement the echo ping pong
		}
		close(msgchan)
		conn.Close()
	}()

	return msgchan, nil
}

// SendMessage sends a "Message"
func (sc *SessionContext) SendMessage(m Message) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = handlerPanicHandler("SendMessage: ", r)
		}
	}()

	conn, err := net.Dial("tcp", "g-33.0.threema.ch:5222")
	if err != nil {
		return err
	}
	defer conn.Close()

	//handshake
	Info.Println("Initiating Handshake")
	sc.dispatchClientHello(conn)
	sc.handleServerHello(receiveHelper(conn, 80))
	sc.dispatchAuthMsg(conn)
	sc.handleHandshakeAck(receiveHelper(conn, 32))
	Info.Println("Handshake Completed")

	// first we have to receive all messages in queue and wait for the connectionEstablished packet
recv:
	for {
		pktIntf, err := sc.receivePacket(conn)
		if err != nil {
			return err
		}

		switch pktIntf.(type) {
		case connEstPacket:
			Info.Println("Connection established.")
			break recv
		}
	}

	sc.dispatchMessage(conn, m)

	return nil
}

// SendTextMessage sends a Text Message to the specified ID
// Enqueued messages will be received, not acknowledged and discarded
func (sc *SessionContext) SendTextMessage(recipient string, text string) (err error) {
	// build a message
	tm, err := newTextMessage(sc, recipient, text)

	if err != nil {
		return err
	}
	return sc.SendMessage(tm)
}

// SendImageMessage sends a Image Message to the specified ID
// Enqueued messages will be received, not acknowledged and discarded
func (sc *SessionContext) SendImageMessage(recipient string, filename string) (err error) {
	// build a message
	im, err := newImageMessage(sc, recipient, filename)

	if err != nil {
		return err
	}

	return sc.SendMessage(im)
}

// SendAudioMessage sends a Audio Message to the specified ID
// Enqueued messages will be received, not acknowledged and discarded
// Works with various audio formats threema uses some kind of mp4 but mp3 works fine
func (sc *SessionContext) SendAudioMessage(recipient string, filename string) (err error) {
	// build a message
	am, err := newAudioMessage(sc, recipient, filename)

	if err != nil {
		return err
	}

	return sc.SendMessage(am)
}

// CreateNewGroup Creates a new group and notifies all members
func (sc *SessionContext) CreateNewGroup(group Group) (groupID [8]byte, err error) {

	group.GroupID = NewGrpID()

	sc.ChangeGroupMembers(group)
	if err != nil {
		return groupID, err
	}

	sc.RenameGroup(group)
	if err != nil {
		return groupID, err
	}

	return groupID, nil
}

// RenameGroup Sends a message with the new group name to all members
func (sc *SessionContext) RenameGroup(group Group) (err error) {

	sgn := newGroupManageSetNameMessages(sc, group)
	for _, msg := range sgn {
		err = sc.SendMessage(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

// ChangeGroupMembers Sends a message with the new group member list to all members
func (sc *SessionContext) ChangeGroupMembers(group Group) (err error) {

	sgm := newGroupManageSetMembersMessages(sc, group)
	for _, msg := range sgm {
		err = sc.SendMessage(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

// LeaveGroup Sends a message to all members telling them the sender left the group
func (sc *SessionContext) LeaveGroup(group Group) (err error) {

	sgm := newGroupMemberLeftMessages(sc, group)
	for _, msg := range sgm {
		err = sc.SendMessage(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (sc *SessionContext) receivePacket(reader io.Reader) (pkt interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = handlerPanicHandler("receivePacket", r)
		}
	}()

	length, err := receivePacketLength(reader)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, length)
	n, err := reader.Read(buf)
	if n != int(length) {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Packet of invalid length received. Expected: %d; received: %d\n", length, n)
	}

	pkt = sc.handleClientServerMsg(bytes.NewBuffer(buf))
	return pkt, nil
}

func receivePacketLength(reader io.Reader) (uint16, error) {
	lbuf := make([]byte, 2)
	var length uint16
	n, err := reader.Read(lbuf)
	if n != 2 {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("No parseable packet length received\n")
	}
	err = binary.Read(bytes.NewBuffer(lbuf), binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}
	return length, nil
}
