package o3

import (
	"encoding/base64"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pkg/errors"
)

func TestAliceBob(t *testing.T) {
	aliceCtx := initSession(t, "test/idAlice", "test/idAlice.ab", "ThisIsAlice1")
	bobCtx := initSession(t, "test/idBob", "test/idBob.ab", "ThisIsBob234")

	var wg sync.WaitGroup
	wg.Add(2)

	aToBMsg := randString(30)
	go pingPong(t, &wg, aToBMsg, bobCtx.ID.String(), &aliceCtx)
	go pingPong(t, &wg, aToBMsg, aliceCtx.ID.String(), &bobCtx)

	wg.Wait()
	t.Log("all done!")
}

func pingPong(t *testing.T,
	wg *sync.WaitGroup,
	testMsg, remoteID string,
	ctx *SessionContext) {

	sendChan, recvChan, err := ctx.Run()
	if err != nil {
		t.Fatal(errors.Wrap(err, "context couldnt run"))
	}

	if msg, err := NewTextMessage(ctx, remoteID, testMsg); err != nil {
		t.Fatal(errors.Wrapf(err, "%s: couldn't send her message", ctx.ID.String()))
	} else {
		sendChan <- &msg
	}
	t.Logf("%s send message", ctx.ID.String())
	for msg := range recvChan {
		t.Logf("%s receiverd a message", ctx.ID.String())
		if err := msg.Err; err != nil {
			t.Error(errors.Wrapf(err, "error on %s recv channel", ctx.ID.String()))
			continue
		}
		switch thisMsg := msg.Msg.(type) {

		case *TextMessage:
			if remoteID == thisMsg.Sender.String() {
				if txt := thisMsg.String(); txt != testMsg {
					t.Errorf("%s: got wrong message back. Wanted: %q got %q", ctx.ID.String(), testMsg, txt)
				}
				wg.Done()
				continue
			}
		default:
			t.Logf("unhandled message type: %T", msg)
		}
	}
}

func initSession(t *testing.T, idpath, abpath, pass string) SessionContext {
	passw, err := base64.StdEncoding.DecodeString(pass)
	if err != nil {
		t.Fatal(errors.Wrapf(err, "could not decode id(%s) password", idpath))
	}

	tid, err := LoadIDFromFile(idpath, passw)
	if err != nil {
		t.Fatal(errors.Wrapf(err, "could not load id(%s)", idpath))
	}

	t.Logf("loaded ID(%s): %s", idpath, tid)

	_, nick := filepath.Split(idpath)

	tid.Nick = NewPubNick(nick)
	ctx := NewSessionContext(tid)

	if err := ctx.ID.Contacts.ImportFrom(abpath); err != nil {
		t.Fatal(errors.Wrap(err, "could not load address book"))
	}

	go func() {
		for e := range ctx.ErrorChan {
			t.Fatal(errors.Wrapf(e, "%s: error on ctx.ErrorChan", idpath))
		}
	}()

	return ctx
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
