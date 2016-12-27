package o3

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// uploadBlob Uploads a blob to the threema servers and returns the assigned blob ID
func uploadBlob(blob []byte) ([16]byte, error) {
	// Load Threema Server Cert
	CAPool := x509.NewCertPool()
	severCert, err := ioutil.ReadFile("./cert.pem")
	if err != nil {
		return [16]byte{}, errors.New("Could not load server certificate!")
	}
	CAPool.AppendCertsFromPEM(severCert)

	config := tls.Config{RootCAs: CAPool}

	tr := &http.Transport{
		TLSClientConfig: &config,
	}
	client := &http.Client{Transport: tr}

	var imageBuf bytes.Buffer
	mulipartWriter := multipart.NewWriter(&imageBuf)

	part, err := mulipartWriter.CreateFormFile("blob", "blob.bin")

	io.Copy(part, bytes.NewReader(blob))
	mulipartWriter.Close()

	url := "https://upload.blob.threema.ch/upload"

	req, err := http.NewRequest("POST", url, &imageBuf)
	if err != nil {
		return [16]byte{}, err
	}

	req.Header.Set("User-Agent", "Threema/2.8")
	req.Header.Set("Content-Type", mulipartWriter.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return [16]byte{}, err
	}
	if resp.StatusCode != 200 {
		return [16]byte{}, errors.New("Could not load server certificate!")
	}

	blobIDraw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return [16]byte{}, err
	}

	blobIDbytes, err := hex.DecodeString(string(blobIDraw))
	if err != nil {
		return [16]byte{}, err
	}

	var blobID [16]byte
	copy(blobID[:], blobIDbytes)

	return blobID, nil
}

// encryptAsymAndUpload encrypts a blob with recipients PK and the sc owners SK
func encryptAndUploadAsym(sc SessionContext, plainImage []byte, recipientName string) (blobNonce nonce, ServerID byte, size uint32, blobID [16]byte, err error) {
	// Get contact public key
	threemaID := sc.ID
	recipient, inContacts := threemaID.Contacts.Get(recipientName)
	if !inContacts {
		var tr ThreemaRest
		recipient, err = tr.GetContactByID(NewIdString(recipientName))
		if err != nil {
			return nonce{}, 0, 0, [16]byte{}, err
		}
	}

	blobNonce = newRandomNonce()
	ciphertext := box.Seal(nil, plainImage, blobNonce.bytes(), &recipient.LPK, &threemaID.LSK)

	blobID, err = uploadBlob(ciphertext)
	if err != nil {
		return nonce{}, 0, 0, [16]byte{}, err
	}

	return blobNonce, blobID[0], uint32(len(ciphertext)), blobID, nil
}

// encryptAsymAndUpload encrypts a blob with recipients PK and the sc owners SK
func encryptAndUploadSym(plainImage []byte) (key [32]byte, ServerID byte, size uint32, blobID [16]byte, err error) {
	// fixed nonce of the form [000000....1]
	nonce := [24]byte{}
	nonce[23] = 1
	// new random Key
	sharedKey := new([32]byte)
	_, err = io.ReadFull(rand.Reader, sharedKey[:])
	if err != nil {
		sharedKey = nil
		return [32]byte{}, 0, 0, [16]byte{}, err
	}
	ciphertext := secretbox.Seal(nil, plainImage, &nonce, sharedKey)

	blobID, err = uploadBlob(ciphertext)
	if err != nil {
		return [32]byte{}, 0, 0, [16]byte{}, err
	}

	return *sharedKey, blobID[0], uint32(len(ciphertext)), blobID, nil
}

//
func downloadBlob(blobID [16]byte) ([]byte, error) {
	// Load Threema Server Cert
	CAPool := x509.NewCertPool()
	severCert, err := ioutil.ReadFile("./cert.pem")
	if err != nil {
		return []byte{}, errors.New("Could not load server certificate!")
	}
	CAPool.AppendCertsFromPEM(severCert)

	config := tls.Config{RootCAs: CAPool}

	tr := &http.Transport{
		TLSClientConfig: &config,
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%.2x.blob.threema.ch/%x", blobID[0], blobID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, err
	}

	req.Header.Set("User-Agent", "Threema/2.8")

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}
	if resp.StatusCode != 200 {
		return []byte{}, fmt.Errorf("Downloading blob failed: %s", resp.Status)
	}

	defer resp.Body.Close()
	ciphertext, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	return ciphertext, nil
}

func downloadAndDecryptAsym(sc SessionContext, blobID [16]byte, senderName string, blobNonce nonce) (plaintext []byte, err error) {
	ciphertext, err := downloadBlob(blobID)
	if err != nil {
		return []byte{}, err
	}

	var sender ThreemaContact
	threemaID := sc.ID
	sender, inContacts := threemaID.Contacts.Get(senderName)
	if !inContacts {
		var tr ThreemaRest
		sender, err = tr.GetContactByID(NewIdString(senderName))
		if err != nil {
			return []byte{}, err
		}
	}

	plainPicture, success := box.Open(nil, ciphertext, blobNonce.bytes(), &sender.LPK, &threemaID.LSK)
	if !success {
		return []byte{}, errors.New("Could not decrypt image message!")
	}

	return plainPicture, nil
}

func downloadAndDecryptSym(blobID [16]byte, key [32]byte) (plaintext []byte, err error) {
	ciphertext, err := downloadBlob(blobID)
	if err != nil {
		return []byte{}, err
	}

	// fixed nonce of the form [000000....1]
	nonce := [24]byte{}
	nonce[23] = 1
	plainPicture, success := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !success {
		return []byte{}, errors.New("Could not decrypt image message!")
	}

	return plainPicture, nil
}
