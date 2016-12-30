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

// Run receives all enqueued Messages and writes the results
// to the channel passed as argument
func (sc *SessionContext) Run() (chan<- Message, <-chan ReceivedMsg, error) {
	defer func() {
		if r := recover(); r != nil {
			// TODO: Return the error
			handlerPanicHandler("Receive Messages", r)
		}
	}()

	var err error
	sc.connection, err = net.Dial("tcp", "g-33.0.threema.ch:5222")
	if err != nil {
		return nil, nil, err
	}

	//handshake
	//Info.Println("Initiating Handshake")
	sc.dispatchClientHello(sc.connection)
	sc.handleServerHello(receiveHelper(sc.connection, 80))
	sc.dispatchAuthMsg(sc.connection)
	sc.handleHandshakeAck(receiveHelper(sc.connection, 32))
	//Info.Println("Handshake Completed")

	sc.sendMsgChan = make(chan Message)
	sc.receiveMsgChan = make(chan ReceivedMsg)

	// receiveLoop calls sendLoop when ready
	go sc.receiveLoop()

	return sc.sendMsgChan, sc.receiveMsgChan, nil
}

func (sc *SessionContext) receiveLoop() {
	defer sc.connection.Close()
	//recv:
	for {
		pktIntf, err := sc.receivePacket(sc.connection)
		if err != nil {
			if err == io.EOF {
				//break recv
				return
			}
			//Error.Printf("receivePacket failed: %s", err)
			sc.receiveMsgChan <- ReceivedMsg{
				Msg: nil,
				Err: err,
			}

			// TODO: break/return on specific errors - i.e. connection reset
			continue
		}
		switch pkt := pktIntf.(type) {
		case messagePacket:
			// Acknowledge message packet
			sc.dispatchAckMsg(sc.connection, pkt)

			// Get the actual message
			var rmsg ReceivedMsg
			rmsg.Msg, rmsg.Err = sc.handleMessagePacket(pkt)
			sc.receiveMsgChan <- rmsg
		case ackPacket:
			// ok cool. nothing to do.
		case connEstPacket:
			//Info.Printf("Got Message: %#v\n", pkt)
			go sc.sendLoop()
		default:
			fmt.Printf("ReceiveMessages: unhandled packet type: %T", pkt)
			return
		}
		// TODO: Implement the echo ping pong
	}

}

func (sc *SessionContext) sendLoop() {
	for msg := range sc.sendMsgChan {
		sc.dispatchMessage(sc.connection, msg)
	}
}

// SendTextMessage sends a Text Message to the specified ID
// Enqueued messages will be received, not acknowledged and discarded
func (sc *SessionContext) SendTextMessage(recipient string, text string, sendMsgChan chan<- Message) error {
	// build a message
	tm, err := NewTextMessage(sc, recipient, text)

	// TODO: error handling
	if err != nil {
		return err
	}

	sendMsgChan <- tm

	return nil
}

// SendImageMessage sends a Image Message to the specified ID
// Enqueued messages will be received, not acknowledged and discarded
func (sc *SessionContext) SendImageMessage(recipient string, filename string, sendMsgChan chan<- Message) error {
	// build a message
	im, err := NewImageMessage(sc, recipient, filename)

	if err != nil {
		return err
	}

	sendMsgChan <- im

	return nil
}

// SendAudioMessage sends a Audio Message to the specified ID
// Enqueued messages will be received, not acknowledged and discarded
// Works with various audio formats threema uses some kind of mp4 but mp3 works fine
func (sc *SessionContext) SendAudioMessage(recipient string, filename string, sendMsgChan chan<- Message) error {
	// build a message
	am, err := NewAudioMessage(sc, recipient, filename)

	if err != nil {
		return err
	}

	sendMsgChan <- am

	return nil
}

// CreateNewGroup Creates a new group and notifies all members
func (sc *SessionContext) CreateNewGroup(group Group, sendMsgChan chan<- Message) (groupID [8]byte, err error) {

	group.GroupID = NewGrpID()

	sc.ChangeGroupMembers(group, sendMsgChan)
	if err != nil {
		return groupID, err
	}

	sc.RenameGroup(group, sendMsgChan)
	if err != nil {
		return groupID, err
	}

	return groupID, nil
}

// RenameGroup Sends a message with the new group name to all members
func (sc *SessionContext) RenameGroup(group Group, sendMsgChan chan<- Message) (err error) {

	sgn := NewGroupManageSetNameMessages(sc, group)
	for _, msg := range sgn {
		sendMsgChan <- msg
	}

	return nil
}

// ChangeGroupMembers Sends a message with the new group member list to all members
func (sc *SessionContext) ChangeGroupMembers(group Group, sendMsgChan chan<- Message) (err error) {

	sgm := NewGroupManageSetMembersMessages(sc, group)
	for _, msg := range sgm {
		sendMsgChan <- msg
	}

	return nil
}

// LeaveGroup Sends a message to all members telling them the sender left the group
func (sc *SessionContext) LeaveGroup(group Group, sendMsgChan chan<- Message) (err error) {

	sgm := NewGroupMemberLeftMessages(sc, group)
	for _, msg := range sgm {
		sendMsgChan <- msg
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
		return nil, fmt.Errorf("packet of invalid length received. Expected: %d; received: %d", length, n)
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
		return 0, fmt.Errorf("no parseable packet length received")
	}
	err = binary.Read(bytes.NewBuffer(lbuf), binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}
	return length, nil
}
