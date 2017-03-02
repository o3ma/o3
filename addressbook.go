package o3

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"fmt"
)
import "os"

// ThreemaContact is the  core contact type, comprising of
// an ID, a long-term public key, and an optional Nickname, FirstName
// and LastName
type ThreemaContact struct {
	ID        IDString
	PubNick   string
	LPK       [32]byte
	FirstName string
	LastName  string
}

func (tc ThreemaContact) String() string {
	return string(tc.ID[:])
}

// AddressBook is the register of ThreemaContacts
type AddressBook struct {
	contacts map[string]ThreemaContact
}

func (a AddressBook) slice() [][]string {
	buf := make([][]string, len(a.contacts))
	i := 0
	for _, contact := range a.contacts {
		buf[i] = make([]string, 5)
		buf[i][0] = string(contact.ID[:])
		buf[i][1] = contact.PubNick
		buf[i][2] = hex.EncodeToString(contact.LPK[:])
		buf[i][3] = contact.FirstName
		buf[i][4] = contact.LastName
		i++
	}
	return buf
}

func (a *AddressBook) initializeMap(c int) {
	a.contacts = make(map[string]ThreemaContact, c)
}

// Import takes a two-dimensional slice of strings and imports it
// field by field into the address book.
// Fields have to be in the order "ID, PubNick, LPK, FirstName, LastName" or the
// function will return an error
func (a *AddressBook) Import(contacts [][]string) error {
	a.contacts = make(map[string]ThreemaContact, len(contacts))

	if a.contacts == nil {
		a.initializeMap(len(contacts))
	}

	for l, c := range contacts {
		// log.Printf("%#v\n", c)
		id := c[0]
		contact := ThreemaContact{PubNick: c[1], FirstName: c[3], LastName: c[4]}
		n := copy(contact.ID[:], id[:])
		if n != 8 {
			return fmt.Errorf("line %d: invalid ID length: %d", l, n)
		}
		lpk, err := hex.DecodeString(c[2])
		if err != nil {
			return err
		}
		n = copy(contact.LPK[0:32], lpk[0:32])
		if n != 32 {
			return fmt.Errorf("line %d: invalid pubKey length: %d", l, n)
		}
		a.contacts[id] = contact
	}
	return nil
}

// LoadFromFile imports an address book stored in a CSV file
func (a *AddressBook) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	rdr := csv.NewReader(file)
	lines, err := rdr.ReadAll()
	// log.Printf("Read lines: %#v\n", lines)
	if err != nil {
		return err
	}
	return a.Import(lines)
}

// SaveTo stores the AddressBook in the file with the given name
// in CSV format
func (a AddressBook) SaveTo(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	wrtr := csv.NewWriter(file)
	slice := a.slice()
	return wrtr.WriteAll(slice)
}

// Add takes a ThreemaContact and adds it to the AddressBook
func (a *AddressBook) Add(c ThreemaContact) {
	id := string(c.ID[:])
	if a.contacts == nil {
		a.initializeMap(1)
	}
	a.contacts[id] = c
}

// Get returns a ThreemaContact to a given ID. It returns an empty ThreemaContact
// if no entry is found. The second parameter can be used to check if
// retrieval was successful
func (a AddressBook) Get(id string) (ThreemaContact, bool) {
	contact := a.contacts[id]
	//checking if an empty ThreemaContact was returned
	if bytes.Equal(contact.ID[:], []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		return contact, false
	}
	return contact, true
}

// Contacts returns the map of id strings to contact structs of all contacts in the address book
func (a AddressBook) Contacts() map[string]ThreemaContact {
	return a.contacts
}
