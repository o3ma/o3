package o3

import (
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"time"

	"errors"
)

// MsgType determines the type of message that is sent or received. Users usually
// won't use this directly and rather use message generator functions.
type MsgType uint8

// MsgType mock enum
const (
	TEXTMESSAGE             MsgType = 0x1  //indicates a text message
	UNKNOWN_TYPE_1          MsgType = 0x1A //indicates a text message
	IMAGEMESSAGE            MsgType = 0x2  //indicates a image message
	AUDIOMESSAGE            MsgType = 0x14 //indicates a audio message
	POLLMESSAGE             MsgType = 0x15 //indicates a poll message
	LOCATIONMESSAGE         MsgType = 0x16 //indicates a location message
	FILEMESSAGE             MsgType = 0x17 //indicates a file message
	GROUPTEXTMESSAGE        MsgType = 0x41 //indicates a group text message
	GROUPIMAGEMESSAGE       MsgType = 0x43 //indicates a group image message
	GROUPSETMEMEBERSMESSAGE MsgType = 0x4A //indicates a set group member message
	GROUPSETNAMEMESSAGE     MsgType = 0x4B //indicates a set group name message
	GROUPMEMBERLEFTMESSAGE  MsgType = 0x4C //indicates a group member left message
	GROUPSETIMAGEMESSAGE    MsgType = 0x50 //indicates a group set image message
	DELIVERYRECEIPT         MsgType = 0x80 //indicates a delivery receipt sent by the threema servers
	TYPINGNOTIFICATION      MsgType = 0x90 //indicates a typing notifiaction message
	//GROUPSETIMAGEMESSAGE msgType = 76
)

// MsgStatus represents the single-byte status field of DeliveryReceiptMessage
type MsgStatus uint8

//MsgStatus mock enum
const (
	MSGDELIVERED   MsgStatus = 0x1 //indicates message was received by peer
	MSGREAD        MsgStatus = 0x2 //indicates message was read by peer
	MSGAPPROVED    MsgStatus = 0x3 //indicates message was approved (thumb up) by peer
	MSGDISAPPROVED MsgStatus = 0x4 //indicates message was disapproved (thumb down) by peer
)

//TODO: figure these out
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

func (mh messageHeader) Recipient() IDString {
	return mh.recipient
}

func (mh messageHeader) ID() uint64 {
	return mh.id
}

func (mh messageHeader) Time() time.Time {
	return mh.time
}

func (mh messageHeader) PubNick() PubNick {
	return mh.pubNick
}

//TODO: WAT?
func (mh messageHeader) header() messageHeader {
	return mh
}

//--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<----

type textMessageBody struct {
	text string
}

//TextMessage represents a text message as sent e2e encrypted to other threema users
type TextMessage struct {
	messageHeader
	textMessageBody
}

// NewTextMessage returns a TextMessage ready to be encrypted
func NewTextMessage(sc *SessionContext, recipient string, text string) (TextMessage, error) {
	recipientID := NewIDString(recipient)

	tm := TextMessage{
		messageHeader{
			sender:    sc.ID.ID,
			recipient: recipientID,
			id:        NewMsgID(),
			time:      time.Now(),
			pubNick:   sc.ID.Nick,
		},
		textMessageBody{text: text},
	}
	return tm, nil
}

// Text returns the message text
func (tm TextMessage) Text() string {
	return tm.text
}

// String returns the message text as string
func (tm TextMessage) String() string {
	return tm.Text()
}

//Serialize returns a fully serialized byte slice of a TextMessage
func (tm TextMessage) Serialize() []byte {
	return serializeTextMsg(tm).Bytes()
}

//Serialize returns a fully serialized byte slice of a TypingNotificationMessage
func (tn TypingNotificationMessage) Serialize() []byte {
	return serializeTypingNotification(tn).Bytes()
}

//--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<----

//ImageMessage represents an image message as sent e2e encrypted to other threema users
type ImageMessage struct {
	messageHeader
	imageMessageBody
}

type imageMessageBody struct {
	BlobID   [16]byte
	ServerID byte
	Size     uint32
	Nonce    nonce
}

// NewImageMessage returns a ImageMessage ready to be encrypted
func NewImageMessage(sc *SessionContext, recipient string, filename string) (ImageMessage, error) {
	recipientID := NewIDString(recipient)

	im := ImageMessage{
		messageHeader{
			sender:    sc.ID.ID,
			recipient: recipientID,
			id:        NewMsgID(),
			time:      time.Now(),
			pubNick:   sc.ID.Nick,
		},
		imageMessageBody{},
	}
	err := im.SetImageData(filename, *sc)
	if err != nil {
		return ImageMessage{}, err
	}
	return im, nil
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

//--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<----

//AudioMessage represents an image message as sent e2e encrypted to other threema users
type AudioMessage struct {
	messageHeader
	audioMessageBody
}

type audioMessageBody struct {
	Duration uint16 // The audio clips duration in seconds
	BlobID   [16]byte
	ServerID byte
	Size     uint32
	Key      [32]byte
}

// NewAudioMessage returns a ImageMessage ready to be encrypted
func NewAudioMessage(sc *SessionContext, recipient string, filename string) (AudioMessage, error) {
	recipientID := NewIDString(recipient)

	im := AudioMessage{
		messageHeader{
			sender:    sc.ID.ID,
			recipient: recipientID,
			id:        NewMsgID(),
			time:      time.Now(),
			pubNick:   sc.ID.Nick,
		},
		audioMessageBody{},
	}
	err := im.SetAudioData(filename, *sc)
	if err != nil {
		return AudioMessage{}, err
	}
	return im, nil
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

//--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<----

//TypingNotificationMessage represents a typing notifiaction message
type TypingNotificationMessage struct {
	messageHeader
	typingNotificationBody
}

type typingNotificationBody struct {
	OnOff byte
}

//--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<----

// NewGroupTextMessages returns a slice of GroupMemberTextMessages ready to be encrypted
func NewGroupTextMessages(sc *SessionContext, group Group, text string) ([]GroupTextMessage, error) {
	gtm := make([]GroupTextMessage, len(group.Members))
	var tm TextMessage
	var err error

	for i, member := range group.Members {
		tm, err = NewTextMessage(sc, member.String(), text)
		if err != nil {
			return []GroupTextMessage{}, err
		}

		gtm[i] = GroupTextMessage{
			groupMessageHeader{
				creatorID: group.CreatorID,
				groupID:   group.GroupID},
			tm}
	}

	return gtm, nil

}

//GroupTextMessage represents a group text message as sent e2e encrypted to other threema users
type GroupTextMessage struct {
	groupMessageHeader
	TextMessage
}

type groupMessageHeader struct {
	creatorID IDString
	groupID   [8]byte
}

// Serialize : returns byte representation of serialized group text message
func (gtm GroupTextMessage) Serialize() []byte {
	return serializeGroupTextMsg(gtm).Bytes()
}

type groupImageMessageBody struct {
	BlobID   [16]byte
	ServerID byte
	Size     uint32
	Key      [32]byte
}

// GroupCreator returns the ID of the groups admin/creator as string
func (gmh groupMessageHeader) GroupCreator() IDString {
	return gmh.creatorID
}

// GroupID returns the ID of the group the message belongs to
func (gmh groupMessageHeader) GroupID() [8]byte {
	return gmh.groupID
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

// SetImageData encrypts the given image symmetrically and adds it to the message
func (im *GroupImageMessage) SetImageData(filename string) error {
	return im.groupImageMessageBody.setImageData(filename)
}

func (im *groupImageMessageBody) setImageData(filename string) error {
	plainImage, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("could not load image")
	}

	im.Key, im.ServerID, im.Size, im.BlobID, err = encryptAndUploadSym(plainImage)

	return err
}

// NewGroupMemberLeftMessages returns a slice of GroupMemberLeftMessages ready to be encrypted
func NewGroupMemberLeftMessages(sc *SessionContext, group Group) []GroupMemberLeftMessage {
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
				pubNick:   sc.ID.Nick}}

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

// NewDeliveryReceiptMessage returns a TextMessage ready to be encrypted
func NewDeliveryReceiptMessage(sc *SessionContext, recipient string, msgID uint64, msgStatus MsgStatus) (DeliveryReceiptMessage, error) {
	recipientID := NewIDString(recipient)

	dm := DeliveryReceiptMessage{
		messageHeader{
			sender:    sc.ID.ID,
			recipient: recipientID,
			id:        NewMsgID(),
			time:      time.Now(),
			pubNick:   sc.ID.Nick,
		},
		deliveryReceiptMessageBody{
			msgID:  msgID,
			status: msgStatus},
	}
	return dm, nil
}

type deliveryReceiptMessageBody struct {
	status MsgStatus
	msgID  uint64
}

// DeliveryReceiptMessage represents a delivery receipt as sent e2e encrypted to other threema users when a message has been received
type DeliveryReceiptMessage struct {
	messageHeader
	deliveryReceiptMessageBody
}

// GetPrintableContent returns a printable represantion of a DeliveryReceiptMessage.
func (dm DeliveryReceiptMessage) GetPrintableContent() string {
	return fmt.Sprintf("Delivered: %x", dm.msgID)
}

//Serialize returns a fully serialized byte slice of a SeliveryReceiptMessage
func (dm DeliveryReceiptMessage) Serialize() []byte {
	return serializeDeliveryReceiptMsg(dm).Bytes()
}

// Status returns the messages status
func (dm DeliveryReceiptMessage) Status() MsgStatus {
	return dm.status
}

// MsgID returns the message id
func (dm DeliveryReceiptMessage) MsgID() uint64 {
	return dm.msgID
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

// NewGroupManageSetMembersMessages returns a slice of GroupManageSetMembersMessages ready to be encrypted
func NewGroupManageSetMembersMessages(sc *SessionContext, group Group) []GroupManageSetMembersMessage {
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
				pubNick:   sc.ID.Nick},
			groupManageSetMembersMessageBody{
				groupMembers: group.Members}}

	}

	return gms

}

type groupManageSetMembersMessageBody struct {
	groupMembers []IDString
}

// GroupManageSetImageMessage represents the message sent e2e-encrypted by a group's creator to all members to set the group image
type GroupManageSetImageMessage struct {
	groupManageMessageHeader
	messageHeader
	groupImageMessageBody
}

// NewGroupManageSetImageMessages returns a slice of GroupManageSetImageMessages ready to be encrypted
func NewGroupManageSetImageMessages(sc *SessionContext, group Group, filename string) []GroupManageSetImageMessage {
	gms := make([]GroupManageSetImageMessage, len(group.Members))

	for i := 0; i < len(group.Members); i++ {
		gms[i] = GroupManageSetImageMessage{
			groupManageMessageHeader{
				groupID: group.GroupID},
			messageHeader{}, //TODO:
			groupImageMessageBody{},
		}

		err := gms[i].SetImageData(filename)
		if err != nil {
			//TODO: pretty sure this isn't a good idea
			return nil
		}
	}

	return gms
}

// GetImageData returns the decrypted Image
func (im GroupManageSetImageMessage) GetImageData(sc SessionContext) ([]byte, error) {
	return downloadAndDecryptSym(im.BlobID, im.Key)
}

// SetImageData encrypts the given image symmetrically and adds it to the message
func (im *GroupManageSetImageMessage) SetImageData(filename string) error {
	return im.groupImageMessageBody.setImageData(filename)
}

//Serialize returns a fully serialized byte slice of an ImageMessage
func (im GroupManageSetImageMessage) Serialize() []byte {
	return serializeGroupManageSetImageMessage(im).Bytes()
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

// NewGroupManageSetNameMessages returns a slice of GroupMenageSetNameMessages ready to be encrypted
func NewGroupManageSetNameMessages(sc *SessionContext, group Group) []GroupManageSetNameMessage {
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
				pubNick:   sc.ID.Nick},
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
