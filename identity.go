package o3

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/salsa20"
)

type PubNick [32]byte

func (pn PubNick) String() string {
	return string(pn[:])
}

func NewPubNick(pb string) PubNick {
	var buf PubNick
	copy(buf[:], []byte(pb))
	return buf
}

// IdString is a Threema ID string
type IdString [8]byte

func (is IdString) String() string {
	return string(is[:])
}

func NewIdString(ids string) IdString {
	var buf IdString
	copy(buf[:], []byte(ids))
	return buf
}

// ThreemaID is the core ID type. It contains the 8-byte ID, its corresponding 32-byte 256-bit private key,
// and a list of known Contacts.
type ThreemaID struct {
	ID       IdString
	Nick     PubNick
	LSK      [32]byte
	Contacts AddressBook
}

// GetPubKey generates the PK on the fly, that's ok because it's rarely needed
func (thid ThreemaID) GetPubKey() *[32]byte {
	publicKey := new([32]byte)
	curve25519.ScalarBaseMult(publicKey, &thid.LSK)
	return publicKey
}

// ReadPassword uses gopass to read a password from the command line without echoing it
func ReadPassword() ([]byte, error) {
	fmt.Printf("Enter identity password: ")

	return gopass.GetPasswd(), nil
}

func decryptID(identity string, password []byte) ([]byte, []byte, error) {
	b32 := strings.NewReplacer("-", "").Replace(identity)
	buf, err := base32.StdEncoding.DecodeString(b32)
	if err != nil {
		return nil, nil, err
	}
	key := genkey(password, buf[0:8])

	plain := make([]byte, 42)
	cipher := buf[8:]
	salsa20.XORKeyStream(plain, cipher, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, &key)

	shasum := sha256.Sum256(plain[0:40])

	if bytes.Equal(shasum[0:2], plain[40:42]) {
		id := plain[0:8]
		pk := plain[8:40]
		//Trace.Printf("Decrypted public key: %#v\n", pk)
		return id, pk, nil

	}
	return nil, nil, errors.New("Verification failed. Wrong password?")
}

func genkey(password, salt []byte) [32]byte {
	keyslice := pbkdf2.Key(password, salt[0:8], 100000, 32, sha256.New)
	var keyarray [32]byte
	copy(keyarray[:], keyslice[:32])
	return keyarray
}

func encryptID(id, pk, password []byte) (string, error) {
	salt := make([]byte, 8)
	n, err := rand.Read(salt)
	if err != nil {
		return "", err
	} else if n != 8 {
		return "", errors.New("Could not acquire random bytes for ID encryption")
	}
	key := genkey(password, salt)

	plain := append(id, pk...)
	chksum := sha256.Sum256(plain[0:40])
	plain = append(plain, chksum[0:2]...)
	cipher := make([]byte, 42)
	salsa20.XORKeyStream(cipher, plain, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, &key)

	buf := append(salt, cipher...)
	buf32 := base32.StdEncoding.EncodeToString(buf)

	ret := ""
	for i, c := range buf32 {
		if (i+1)%4 == 0 {
			ret += string(c)
			if i != len(buf32)-1 {
				ret += "-"
			}
		} else {
			ret += string(c)
		}
	}
	fmt.Printf(ret)
	return ret, nil
}

// LoadIDFromFile will open a Threema identity backup file and parse its base32-encoded encrypted ID using
// the provided password into a ThreemaID
func LoadIDFromFile(filename string, password []byte) (ThreemaID, error) {
	file, err := os.Open(filename)
	if err != nil {
		return ThreemaID{}, err
	}
	defer file.Close()

	buf := make([]byte, 100)

	n, err := file.Read(buf)
	if err != nil {
		return ThreemaID{}, err
	} else if n != 100 {
		return ThreemaID{}, errors.New("File does not contain a valid ID")
	}

	return ParseIDBackupString(string(buf), password)
}

// ParseIDString parses the base32-encoded encrypted ID string contained in a threema backup.
func ParseIDBackupString(idstr string, password []byte) (ThreemaID, error) {
	threemaID := ThreemaID{}
	id, lsk, err := decryptID(idstr, password)
	if err != nil {
		return threemaID, err
	}
	copy(threemaID.ID[:], id[0:8])
	copy(threemaID.LSK[:], lsk[0:32])

	return threemaID, nil
}

// SaveToFile exports a ThreemaID to the given filename encrypted with password. It uses Threema's
// identity export format so the backup can be re-imported both here and in the app. Note that the result
// will always look different even if using the same password and ID because the salt is re-generated
// with each backup.
func (id ThreemaID) SaveToFile(filename string, password []byte) error {
	idstr, err := encryptID(id.ID[:], id.LSK[:], password)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, []byte(idstr), 0600)
}

// NewThreemaID creates a ThreemaID from a given id strnig and a 256-bit private key
func NewThreemaID(id string, lsk [32]byte, contacts AddressBook) (ThreemaID, error) {
	var tid ThreemaID

	if len(id) != 8 {
		return tid, errors.New("Length of Threema ID must be exactly 8")
	}
	copy(tid.ID[:], id[:])
	tid.LSK = lsk

	tid.Contacts = contacts

	return tid, nil
}

func (id ThreemaID) String() string {
	return string(id.ID[:])
}
