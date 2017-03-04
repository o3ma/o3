package o3

//dynSendChan implements a buffered channel for sending messages with dynamic size. It will
//immediately consume input and store it in a growing FIFO buffer that can be read from using Out.
type dynSendChan struct {
	In  chan Message
	Out chan Message
	buf []Message
}

//newDynSendChan returns a new dynamic sending channel that need not be further initialized to
//be usable.
func newDynSendChan() *dynSendChan {
	d := &dynSendChan{
		In:  make(chan Message),
		Out: make(chan Message),
		buf: make([]Message, 0),
	}
	go d.run()
	return d
}

func (d *dynSendChan) run() {
	for {
		if len(d.buf) > 0 {
			select {
			case d.Out <- d.buf[0]:
				d.buf = d.buf[1:]
			case v := <-d.In:
				d.buf = append(d.buf, v)
			}
		} else {
			v := <-d.In
			d.buf = append(d.buf, v)
		}
	}
}

//dynRecvChan implements a buffered channel for receiving messages with dynamic size. It will
//immediately consume input and store it in a growing FIFO buffer that can be read from using Out.
type dynRecvChan struct {
	In  chan ReceivedMsg
	Out chan ReceivedMsg
	buf []ReceivedMsg
}

//newDynRecvChan returns a new dynamic receiving channel that need not be further initialized to
//be usable.
func newDynRecvChan() *dynRecvChan {
	d := &dynRecvChan{
		In:  make(chan ReceivedMsg),
		Out: make(chan ReceivedMsg),
		buf: make([]ReceivedMsg, 0),
	}
	go d.run()
	return d
}

func (d *dynRecvChan) run() {
	for {
		if len(d.buf) > 0 {
			select {
			case d.Out <- d.buf[0]:
				d.buf = d.buf[1:]
			case v := <-d.In:
				d.buf = append(d.buf, v)
			}
		} else {
			v := <-d.In
			d.buf = append(d.buf, v)
		}
	}
}
