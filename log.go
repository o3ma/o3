package o3

import (
	"io"
	"log"
)

var (
	Trace   *log.Logger = nil
	Info    *log.Logger = nil
	Warning *log.Logger = nil
	Error   *log.Logger = nil
)

func LogInit(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	if Trace == nil {
		SetTraceOutput(traceHandle)
	}
	if Info == nil {
		SetInfoOutput(infoHandle)
	}
	if Warning == nil {
		SetWarningOutput(warningHandle)
	}
	if Error == nil {
		SetErrorOutput(errorHandle)
	}
}

func SetTraceOutput(traceHandle io.Writer) {
	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

func SetInfoOutput(infoHandle io.Writer) {
	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

func SetWarningOutput(warningHandle io.Writer) {
	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

func SetErrorOutput(errorHandle io.Writer) {
	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}
