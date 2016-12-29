package o3

import (
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"time"

	"errors"
)

type msgType uint8

const (
	//TEXTMESSAGE is the msgType used for text messages
	TEXTMESSAGE msgType = 0x1

	//IMAGEMESSAGE is the msgType used for image messages
	IMAGEMESSAGE msgType = 0x2

	//AUDIOMESSAGE is the msgType used for audio messages
	AUDIOMESSAGE msgType = 0x14

	//POLLMESSAGE is the msgType used for poll messages
	POLLMESSAGE msgType = 0x15

	//LOCATIONMESSAGE is the msgType used for location messages
	LOCATIONMESSAGE msgType = 0x16

	//FILEMESSAGE is the msgType used for file messages
	FILEMESSAGE msgType = 0x17

	//GROUPTEXTMESSAGE is the msgType used for group text messages
	GROUPTEXTMESSAGE msgType = 0x41

	//GROUPIMAGEMESSAGE is the msgType used for group image messages
	GROUPIMAGEMESSAGE msgType = 0x43

	//GROUPSETMEMEBERSMESSAGE is the msgType used for set group member messages
	GROUPSETMEMEBERSMESSAGE msgType = 0x4A

	//GROUPSETNAMEMESSAGE is the msgType used for set group name messages
	GROUPSETNAMEMESSAGE msgType = 0x4B

	//GROUPMEMBERLEFTMESSAGE is the msgType used for group member left messages
	GROUPMEMBERLEFTMESSAGE msgType = 0x4C

	//DELIVERYRECEIPT is the msgType used for delivery receipts sent by the threema servers
	DELIVERYRECEIPT msgType = 0x80

	//TYPINGNOTIFICATION is the msgType used for typing notifiaction messages
	TYPINGNOTIFICATION msgType = 0x90

	//GROUPSETIMAGEMESSAGE msgType = 76
)

type msgFlags struct {
	PushMessage                    bool
	NoQueuing                      bool
	NoAckExpected                  bool
	MessageHasAlreadyBeenDelivered bool
	GroupMessage                   bool
}

// NewMsgID returns a randomly generated message ID (not cryptographically secure!)
// TODO: Why mrand?
func NewMsgID() uint64 {
	mrand.Seed(int64(time.Now().Nanosecond()))
	msgID := uint64(mrand.Int63())
	return msgID
}

// NewGrpID returns a randomly generated group ID (not cryptographically secure!)
// TODO: Why mrand?
func NewGrpID() [8]byte {
	mrand.Seed(int64(time.Now().Nanosecond()))

	grpIDbuf := make([]byte, 8)
	mrand.Read(grpIDbuf)

	var grpID [8]byte
	copy(grpID[:], grpIDbuf)

	return grpID
}

// Message representing the various kinds of e2e ecrypted messages threema supports
type Message interface {

	//Sender returns the message's sender ID
	Sender() IDString

	//Serialize returns a fully serialized byte slice of the message
	Serialize() []byte

	header() messageHeader
}

type messageHeader struct {
	sender    IDString
	recipient IDString
	id        uint64
	time      time.Time
	pubNick   PubNick
}

func (mh messageHeader) Sender() IDString {
	return mh.sender
}

func (mh messageHeader) header() messageHeader {
	return mh
}

type textMessageBody struct {
	text string
}

//TextMessage represents a text message as sent e2e encrypted to other threema users
type TextMessage struct {
	messageHeader
	textMessageBody
}

// Text returns the message text
func (tm TextMessage) Text() string {
	return tm.text
}

// String returns the message text as string
func (tm TextMessage) String() string {
	return tm.text
}

//Serialize returns a fully serialized byte slice of a TextMessage
func (tm TextMessage) Serialize() []byte {
	return serializeTextMsg(tm).Bytes()
}

//Serialize returns a fully serialized byte slice of a TypingNotificationMessage
func (tn TypingNotificationMessage) Serialize() []byte {
	return serializeTypingNotification(tn).Bytes()
}

// newTextMessage returns a TextMessage ready to be encrypted
func newTextMessage(sc *SessionContext, recipient string, text string) (TextMessage, error) {
	recipientID, ok := sc.ID.Contacts.Get(recipient)
	if !ok {
		return TextMessage{}, fmt.Errorf("Cannot find recipient in contacts: %s", recipient)
	}

	tm := TextMessage{
		messageHeader{
			sender:    sc.ID.ID,
			recipient: recipientID.ID,
			id:        NewMsgID(),
			time:      time.Now(),
			pubNick:   NewPubNick(sc.ID.String()),
		},
		textMessageBody{text: text},
	}
	return tm, nil
}

// newImageMessage returns a ImageMessage ready to be encrypted
func newImageMessage(sc *SessionContext, recipient string, filename string) (ImageMessage, error) {
	recipientID, ok := sc.ID.Contacts.Get(recipient)
	if !ok {
		return ImageMessage{}, fmt.Errorf("Cannot find recipient in contacts: %s", recipient)
	}

	im := ImageMessage{
		messageHeader{
			sender:    sc.ID.ID,
			recipient: recipientID.ID,
			id:        NewMsgID(),
			time:      time.Now(),
			pubNick:   NewPubNick(sc.ID.String()),
		},
		imageMessageBody{},
	}
	err := im.SetImageData(filename, *sc)
	if err != nil {
		return ImageMessage{}, err
	}
	return im, nil
}

type imageMessageBody struct {
	BlobID   [16]byte
	ServerID byte
	Size     uint32
	Nonce    nonce
}

//ImageMessage represents an image message as sent e2e encrypted to other threema users
type ImageMessage struct {
	messageHeader
	imageMessageBody
}

// GetPrintableContent returns a printable represantion of a ImageMessage.
func (im ImageMessage) GetPrintableContent() string {
	return fmt.Sprintf("ImageMSG: https://%2x.blob.threema.ch/%16x, Size: %d, Nonce: %24x", im.ServerID, im.BlobID, im.Size, im.Nonce.nonce)
}

// GetImageData return the decrypted Image needs the recipients secret key
func (im ImageMessage) GetImageData(sc SessionContext) ([]byte, error) {
	return downloadAndDecryptAsym(sc, im.BlobID, im.Sender().String(), im.Nonce)
}

// SetImageData encrypts and uploads the image. Sets the blob info in the ImageMessage. Needs the recipients public key.
func (im *ImageMessage) SetImageData(filename string, sc SessionContext) error {
	plainImage, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("could not load image")
	}

	im.Nonce, im.ServerID, im.Size, im.BlobID, err = encryptAndUploadAsym(sc, plainImage, im.recipient.String())

	return err
}

//Serialize returns a fully serialized byte slice of an ImageMessage
func (im ImageMessage) Serialize() []byte {
	return serializeImageMsg(im).Bytes()
}

// newAudioMessage returns a ImageMessage ready to be encrypted
func newAudioMessage(sc *SessionContext, recipient string, filename string) (AudioMessage, error) {
	recipientID, ok := sc.ID.Contacts.Get(recipient)
	if !ok {
		return AudioMessage{}, fmt.Errorf("Cannot find recipient in contacts: %s", recipient)
	}

	im := AudioMessage{
		messageHeader{
			sender:    sc.ID.ID,
			recipient: recipientID.ID,
			id:        NewMsgID(),
			time:      time.Now(),
			pubNick:   NewPubNick(sc.ID.String()),
		},
		audioMessageBody{},
	}
	err := im.SetAudioData(filename, *sc)
	if err != nil {
		return AudioMessage{}, err
	}
	return im, nil
}

type audioMessageBody struct {
	Duration uint16 // The audio clips duration in seconds
	BlobID   [16]byte
	ServerID byte
	Size     uint32
	Key      [32]byte
}

//AudioMessage represents an image message as sent e2e encrypted to other threema users
type AudioMessage struct {
	messageHeader
	audioMessageBody
}

// GetPrintableContent returns a printable represantion of an AudioMessage
func (am AudioMessage) GetPrintableContent() string {
	return fmt.Sprintf("AudioMSG: https://%2x.blob.threema.ch/%16x, Size: %d, Nonce: %24x", am.ServerID, am.BlobID, am.Size, am.Key)
}

// GetAudioData return the decrypted audio, needs the recipients secret key
func (am AudioMessage) GetAudioData(sc SessionContext) ([]byte, error) {
	return downloadAndDecryptSym(am.BlobID, am.Key)
}

// SetAudioData encrypts and uploads the audio. Sets the blob info in the ImageMessage. Needs the recipients public key.
func (am *AudioMessage) SetAudioData(filename string, sc SessionContext) error {
	plainAudio, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("could not load audio")
	}

	// TODO: Should we have a whole media lib as dependency just to set this to the proper value?
	am.Duration = 0xFF

	am.Key, am.ServerID, am.Size, am.BlobID, err = encryptAndUploadSym(plainAudio)

	return err
}

//Serialize returns a fully serialized byte slice of an AudioMessage
func (am AudioMessage) Serialize() []byte {
	return serializeAudioMsg(am).Bytes()
}

// TYPING NOTIFICATIONS
////////////////////////////////////////////////////////////////

//TypingNotificationMessage represents a typing notifiaction message
type TypingNotificationMessage struct {
	messageHeader
	typingNotificationBody
}

type typingNotificationBody struct {
	OnOff byte
}

// GROUP MESSAGES
////////////////////////////////////////////////////////////////

type groupMessageHeader struct {
	creatorID IDString
	groupID   [8]byte
}

// GroupID returns the ID of the group the message belongs to
func (gmh groupMessageHeader) GroupID() [8]byte {
	return gmh.groupID
}

// GroupCreator returns the ID of the groups admin/creator as string
func (gmh groupMessageHeader) GroupCreator() string {
	return gmh.creatorID.String()
}

//GroupTextMessage represents a group text message as sent e2e encrypted to other threema users
type GroupTextMessage struct {
	groupMessageHeader
	TextMessage
}

type groupImageMessageBody struct {
	BlobID   [16]byte
	ServerID byte
	Size     uint32
	Key      [32]byte
}

//GroupImageMessage represents a group image message as sent e2e encrypted to other threema users
type GroupImageMessage struct {
	groupMessageHeader
	messageHeader
	groupImageMessageBody
}

//Serialize returns a fully serialized byte slice of a GroupImageMessage
func (im GroupImageMessage) Serialize() []byte {
	return serializeGroupImageMsg(im).Bytes()
}

// GetImageData return the decrypted Image needs the recipients secret key
func (im GroupImageMessage) GetImageData(sc SessionContext) ([]byte, error) {
	return downloadAndDecryptSym(im.BlobID, im.Key)
}

// SetImageData return the decrypted Image needs the recipients public key
func (im *GroupImageMessage) SetImageData(filename string) error {
	plainImage, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("could not load image")
	}

	im.Key, im.ServerID, im.Size, im.BlobID, err = encryptAndUploadSym(plainImage)

	return err
}

func newGroupMemberLeftMessages(sc *SessionContext, group Group) []GroupMemberLeftMessage {
	gml := make([]GroupMemberLeftMessage, len(group.Members))

	for i := 0; i < len(group.Members); i++ {
		gml[i] = GroupMemberLeftMessage{
			groupMessageHeader{
				creatorID: group.CreatorID,
				groupID:   group.GroupID},
			messageHeader{
				sender:    sc.ID.ID,
				recipient: group.Members[i],
				id:        NewMsgID(),
				time:      time.Now(),
				pubNick:   NewPubNick(sc.ID.String())}}

	}

	return gml

}

//Serialize returns a fully serialized byte slice of a GroupMemberLeftMessage
func (gml GroupMemberLeftMessage) Serialize() []byte {
	return serializeGroupMemberLeftMessage(gml).Bytes()
}

//GroupMemberLeftMessage represents a group leaving message
type GroupMemberLeftMessage struct {
	groupMessageHeader
	messageHeader
}

type deliveryReceiptMessageBody struct {
	MsgID uint64
}

// DeliveryReceiptMessage represents a delivery receipt as sent e2e encrypted to other threema users when a message has been received
type DeliveryReceiptMessage struct {
	messageHeader
	deliveryReceiptMessageBody
}

// GetPrintableContent returns a printable represantion of a DeliveryReceiptMessage.
func (dm DeliveryReceiptMessage) GetPrintableContent() string {
	return fmt.Sprintf("Delivered: %x", dm.MsgID)
}

//Serialize returns a fully serialized byte slice of a SeliveryReceiptMessage
func (dm DeliveryReceiptMessage) Serialize() []byte {
	panic("Not Implemented")
}

// GROUP MANAGEMENT MESSAGES
////////////////////////////////////////////////////////////////
// TODO: Implement message interface
type groupManageMessageHeader struct {
	groupID [8]byte
}

func (gmh groupManageMessageHeader) GroupID() [8]byte {
	return gmh.groupID
}

func newGroupManageSetMembersMessages(sc *SessionContext, group Group) []GroupManageSetMembersMessage {
	gms := make([]GroupManageSetMembersMessage, len(group.Members))

	for i := 0; i < len(group.Members); i++ {
		gms[i] = GroupManageSetMembersMessage{
			groupManageMessageHeader{
				groupID: group.GroupID},
			messageHeader{
				sender:    sc.ID.ID,
				recipient: group.Members[i],
				id:        NewMsgID(),
				time:      time.Now(),
				pubNick:   NewPubNick(sc.ID.String())},
			groupManageSetMembersMessageBody{
				groupMembers: group.Members}}

	}

	return gms

}

type groupManageSetMembersMessageBody struct {
	groupMembers []IDString
}

// GroupManageSetMembersMessage represents the message sent e2e encrypted by a group's creator to all members
type GroupManageSetMembersMessage struct {
	groupManageMessageHeader
	messageHeader
	groupManageSetMembersMessageBody
}

//Members returns a byte slice of IDString of all members contained in the message
func (gmm GroupManageSetMembersMessage) Members() []IDString {
	return gmm.groupMembers
}

//Serialize returns a fully serialized byte slice of a GroupManageSetMembersMessage
func (gmm GroupManageSetMembersMessage) Serialize() []byte {
	return serializeGroupManageSetMembersMessage(gmm).Bytes()
}

func newGroupManageSetNameMessages(sc *SessionContext, group Group) []GroupManageSetNameMessage {
	gms := make([]GroupManageSetNameMessage, len(group.Members))

	for i := 0; i < len(group.Members); i++ {
		gms[i] = GroupManageSetNameMessage{
			groupManageMessageHeader{
				groupID: group.GroupID},
			messageHeader{
				sender:    sc.ID.ID,
				recipient: group.Members[i],
				id:        NewMsgID(),
				time:      time.Now(),
				pubNick:   NewPubNick(sc.ID.String())},
			groupManageSetNameMessageBody{
				groupName: group.Name}}

	}

	return gms

}

type groupManageSetNameMessageBody struct {
	groupName string
}

func (gmm groupManageSetNameMessageBody) Name() string {
	return gmm.groupName
}

//Serialize returns a fully serialized byte slice of a GroupManageSetNameMessage
func (gmm GroupManageSetNameMessage) Serialize() []byte {
	return serializeGroupManageSetNameMessage(gmm).Bytes()
}

//GroupManageSetNameMessage represents a group management messate to set the group name
type GroupManageSetNameMessage struct {
	groupManageMessageHeader
	messageHeader
	groupManageSetNameMessageBody
}
