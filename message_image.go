package o3

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
)

// MsgType mock enum
const MessageTypeImage MsgType = 0x2

//ImageMessage represents a image message as sent e2e encrypted to other threema users
type ImageMessage struct {
	*MessageHeader
	BlobID   [16]byte
	ServerID byte
	Size     uint32
	Nonce    nonce
}

// String returns the message text as string
func (m ImageMessage) String() string {
	return fmt.Sprintf("ImageMSG: https://%2x.blob.threema.ch/%16x, Size: %d, Nonce: %24x", m.ServerID, m.BlobID, m.Size, m.Nonce.nonce)
}

// GetImageData return the decrypted Image needs the recipients secret key
func (m ImageMessage) GetData(threemaID *ThreemaID) ([]byte, error) {
	return downloadAndDecryptAsym(threemaID, m.BlobID, m.Sender.String(), m.Nonce)
}

// SetDataByFile encrypts and uploads the image by file. Sets the blob info in the ImageMessage. Needs the recipients public key.
func (m *ImageMessage) SetDataByFile(threemaID *ThreemaID, filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New("could not load image")
	}
	return m.SetData(threemaID, data)
}

// SetData encrypts and uploads the image. Sets the blob info in the ImageMessage. Needs the recipients public key.
func (m *ImageMessage) SetData(threemaID *ThreemaID, data []byte) (err error) {
	m.Nonce, m.ServerID, m.Size, m.BlobID, err = encryptAsymAndUpload(threemaID, data, m.Recipient.String())
	return
}

//Serialize returns a fully serialized byte slice of a TextMessage
func (m ImageMessage) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	bufMarshal("msg-type", buf, MessageTypeImage)
	bufMarshal("blob-id", buf, m.BlobID)
	bufMarshal("size", buf, m.Size)
	bufMarshal("nonce", buf, m.Nonce.nonce)
	bufMarshalPadding(buf)

	return buf.Bytes(), nil
}

func (m *ImageMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	var t MsgType
	bufUnmarshal("read message type", buf, &t)
	if t != MessageTypeImage {
		return errors.New("not correct type")
	}
	stripPadding(buf)

	bufUnmarshal("blob-id", buf, &m.BlobID)
	bufUnmarshal("size", buf, &m.Size)
	bufUnmarshal("nonce", buf, &m.Nonce.nonce)

	m.ServerID = m.BlobID[0]

	return nil
}

func init() {
	messageUnmarshal[MessageTypeImage] = func(mh *MessageHeader, data []byte) (Message, error) {
		m := &ImageMessage{
			MessageHeader: mh,
		}
		if err := m.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return m, nil
	}
}
