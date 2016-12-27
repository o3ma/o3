package o3

//import (
//	"bytes"
//	"encoding/binary"
//)
//
//type parser func(*bytes.Reader) interface{}
//
//func choice(p ...parser) parser {
//
//	return func(rdr *bytes.Reader) (i interface{}) {
//		rr := *rdr
//		defer func() {
//			if r := recover(); r != nil {
//				*rdr = rr
//				i = choice(p[1:]...)(rdr)
//			}
//		}()
//
//		if p == nil {
//			panic("no parser match")
//		}
//
//		i = p[0](rdr)
//		return
//	}
//}
//
//func parseUint8(r *bytes.Reader) interface{} {
//	var i uint8
//	err := binary.Read(r, binary.LittleEndian, &i)
//	if err != nil {
//		panic(err)
//	}
//	return i
//}
//
//func parseUint16(r *bytes.Reader) interface{} {
//	var i uint16
//
//	if err := binary.Read(r, binary.LittleEndian, &i); err != nil {
//		panic(err)
//	}
//	return i
//}
