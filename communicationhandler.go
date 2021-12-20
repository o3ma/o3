// Package o3 central communication unit responsible for complete exchanges (like handshake and subsequent
// message reception). Uses functions in packethandler and packetdispatcher to deal with incoming
// and outgoing messages. Errors in underlying functions bubble up as panics and have to be re-
// covered here, converted to go errors and returned.
package o3

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var errDuplicateConn = errors.New("duplicate connection Error: this connection was ursurped by another client")

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

// preflightCheck quickly tests the ID and returns an error if it's empty
func (sc *SessionContext) preflightCheck() error {

	check := false
	for _, b := range sc.ID.ID {
		if b != 0x0 {
			check = true
			break
		}
	}
	if !check {
		return errors.New("cannot connect using empty ID")
	}

	check = false
	for _, b := range sc.ID.LSK {
		if b != 0x0 {
			check = true
			break
		}
	}
	if !check {
		return errors.New("cannot connect using empty secret key")
	}

	return nil
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

	//check if we have an ID and LSK to work with
	if err := sc.preflightCheck(); err != nil {
		return nil, nil, err
	}

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

	//TODO: find better way to handle large amounts of offline messages
	//sc.sendMsgChan = make(chan Message, 1000)
	//sc.receiveMsgChan = make(chan ReceivedMsg, 1000)

	// receiveLoop calls sendLoop when ready
	go sc.receiveLoop()

	return sc.sendMsgChan.In, sc.receiveMsgChan.Out, nil
}

func (sc *SessionContext) receiveLoop() {
	defer sc.connection.Close()
	//recv:
	for {
		pktIntf, err := sc.receivePacket(sc.connection)
		if err != nil {
			sc.ErrorChan <- err
			sc.receiveMsgChan.In <- ReceivedMsg{
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
			sc.receiveMsgChan.In <- rmsg
		case ackPacket:
			// ok cool. nothing to do.
		case echoPacket:
			sc.echoCounter = pkt.Counter
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
	defer func() {
		if r := recover(); r != nil {
			switch t := r.(type) {
			case error:
				sc.ErrorChan <- t
			case string:
				sc.ErrorChan <- errors.New(t)
			default:
				sc.ErrorChan <- fmt.Errorf("An unknown error has occurred: %v", r)
			}
		}
	}()
	// Write a new echo pkt to the echPktChan every 3 minutes
	echoPktChan := make(chan echoPacket)
	go func() {
		timeChan := time.Tick(3 * time.Minute)
		for range timeChan {
			ep := echoPacket{PktType: echoMsg,
				Counter: sc.echoCounter}
			echoPktChan <- ep
		}
	}()

	for {
		select {
		case msg := <-sc.sendMsgChan.Out:
			sc.dispatchMessage(sc.connection, msg)
		// Read from echo channel and dispatch (happens every 3 min)
		case echoPkt := <-echoPktChan:
			sc.dispatchEchoMsg(sc.connection, echoPkt)
		}
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

// SendGroupTextMessage Sends a text message to all members
func (sc *SessionContext) SendGroupTextMessage(group Group, text string, sendMsgChan chan<- Message) (err error) {

	tms, err := NewGroupTextMessages(sc, group, text)
	if err != nil {
		return err
	}
	for _, msg := range tms {
		sendMsgChan <- msg
	}

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
	if pkt == errDuplicateConn {
		return nil, errDuplicateConn
	}
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
