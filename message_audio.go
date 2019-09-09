package o3

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
)

// MsgType mock enum
const MessageTypeAudio MsgType = 0x14

//AudioMessage represents a image message as sent e2e encrypted to other threema users
type AudioMessage struct {
	*MessageHeader
	Duration uint16
	BlobID   [16]byte
	ServerID byte
	Size     uint32
	Key      [32]byte
}

// String returns the message text as string
func (m AudioMessage) String() string {
	return fmt.Sprintf("AudioMSG: https://%2x.blob.threema.ch/%16x, Size: %d, Key: %24x", m.ServerID, m.BlobID, m.Size, m.Key)
}

// GetData return the decrypted Audio needs the recipients secret key
func (m AudioMessage) GetData() ([]byte, error) {
	return downloadAndDecryptSym(m.BlobID, m.Key)
}

// SetAudio encrypts and uploads the image by file. Sets the blob info in the AudioMessage. Needs the recipients public key.
func (m *AudioMessage) SetDataByFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("could not load image")
	}
	return m.SetData(data)
}

// SetAudioData encrypts and uploads the image. Sets the blob info in the AudioMessage. Needs the recipients public key.
func (m *AudioMessage) SetData(data []byte) (err error) {
	// TODO: Should we have a whole media lib as dependency just to set this to the proper value?
	m.Duration = 0xFF
	m.Key, m.ServerID, m.Size, m.BlobID, err = encryptSymAndUpload(data)
	return
}

//Serialize returns a fully serialized byte slice of a TextMessage
func (m AudioMessage) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	bufMarshal("msg-type", buf, MessageTypeAudio)
	bufMarshal("duration", buf, 0xFFFF)
	bufMarshal("blob-id", buf, m.BlobID)
	bufMarshal("size", buf, m.Size)
	bufMarshal("nonce", buf, m.Key)
	bufMarshalPadding(buf)

	return buf.Bytes(), nil
}

func (m *AudioMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var t MsgType
	bufUnmarshal("read message type", buf, &t)
	if t != MessageTypeAudio {
		return errors.New("not correct type")
	}
	stripPadding(buf)

	bufUnmarshal("duration", buf, &m.Duration)
	bufUnmarshal("blob-id", buf, &m.BlobID)
	bufUnmarshal("size", buf, &m.Size)
	bufUnmarshal("key", buf, &m.Key)

	m.ServerID = m.BlobID[0]

	return nil
}

func init() {
	messageUnmarshal[MessageTypeAudio] = func(mh *MessageHeader, data []byte) (Message, error) {
		m := &AudioMessage{
			MessageHeader: mh,
		}
		if err := m.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return m, nil
	}
}
