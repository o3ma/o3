package o3

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

var (
	chars = []byte("abcdefghijklmnopqrstuvwxyz")
	caps  = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	nums  = []byte("0123456789")
)

func idString() string {
	rand.Seed(time.Now().Unix() + int64(time.Now().Nanosecond()))
	alph := append(caps, nums...)
	var buf [8]byte
	for i := range buf {
		buf[i] = alph[rand.Intn(len(alph))]
	}
	return string(buf[:])
}

func randString(n int) string {
	rand.Seed(time.Now().Unix())
	alph := append(caps, chars...)
	alph = append(alph, nums...)
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = alph[rand.Intn(len(alph))]
	}
	return string(buf)
}

func members() []IDString {
	rand.Seed(time.Now().Unix())
	buf := make([]IDString, 10)
	r := rand.Intn(10)
	for i := 0; i <= r; i++ {
		buf[i] = NewIDString(idString())
	}
	return buf
}

func randBool() bool {
	r := rand.Intn(2)
	if r == 0 {
		return false
	}
	return true
}

func createGD() GroupDirectory {

	var gd GroupDirectory
	rand.Seed(time.Now().Unix())

	r := rand.Intn(10)

	for i := 0; i < r; i++ {
		gd.groups = append(gd.groups, Group{
			GroupID:   NewGrpID(),
			CreatorID: NewIDString(idString()),
			Name:      randString(32),
			createdAt: time.Unix(rand.Int63(), 0),
			Members:   members(),
			deleted:   randBool(),
		})
	}
	return gd
}

func TestSaveAndImport(t *testing.T) {

	var filename = "groups_test.csv"

	gd := createGD()
	err := gd.SaveToFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	var gd2 GroupDirectory
	err = gd2.LoadFromFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(gd, gd2) {
		t.Fatal("saved and imported GroupDirectories are not equal")
	}
}
