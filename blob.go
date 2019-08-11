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

var threemaCert = []byte{0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0xa, 0x4d, 0x49, 0x49, 0x45, 0x59, 0x54, 0x43, 0x43, 0x41, 0x30, 0x6d, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x4a, 0x41, 0x4d, 0x31, 0x44, 0x52, 0x2f, 0x44, 0x42, 0x52, 0x46, 0x70, 0x51, 0x4d, 0x41, 0x30, 0x47, 0x43, 0x53, 0x71, 0x47, 0x53, 0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x42, 0x42, 0x51, 0x55, 0x41, 0x4d, 0x48, 0x30, 0x78, 0x43, 0x7a, 0x41, 0x4a, 0x42, 0x67, 0x4e, 0x56, 0xa, 0x42, 0x41, 0x59, 0x54, 0x41, 0x6b, 0x4e, 0x49, 0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59, 0x44, 0x56, 0x51, 0x51, 0x49, 0x45, 0x77, 0x4a, 0x61, 0x53, 0x44, 0x45, 0x50, 0x4d, 0x41, 0x30, 0x47, 0x41, 0x31, 0x55, 0x45, 0x42, 0x78, 0x4d, 0x47, 0x57, 0x6e, 0x56, 0x79, 0x61, 0x57, 0x4e, 0x6f, 0x4d, 0x52, 0x41, 0x77, 0x44, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, 0x4b, 0x45, 0x77, 0x64, 0x55, 0xa, 0x61, 0x48, 0x4a, 0x6c, 0x5a, 0x57, 0x31, 0x68, 0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59, 0x44, 0x56, 0x51, 0x51, 0x4c, 0x45, 0x77, 0x4a, 0x44, 0x51, 0x54, 0x45, 0x54, 0x4d, 0x42, 0x45, 0x47, 0x41, 0x31, 0x55, 0x45, 0x41, 0x78, 0x4d, 0x4b, 0x56, 0x47, 0x68, 0x79, 0x5a, 0x57, 0x56, 0x74, 0x59, 0x53, 0x42, 0x44, 0x51, 0x54, 0x45, 0x63, 0x4d, 0x42, 0x6f, 0x47, 0x43, 0x53, 0x71, 0x47, 0xa, 0x53, 0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x4a, 0x41, 0x52, 0x59, 0x4e, 0x59, 0x32, 0x46, 0x41, 0x64, 0x47, 0x68, 0x79, 0x5a, 0x57, 0x56, 0x74, 0x59, 0x53, 0x35, 0x6a, 0x61, 0x44, 0x41, 0x65, 0x46, 0x77, 0x30, 0x78, 0x4d, 0x6a, 0x45, 0x78, 0x4d, 0x54, 0x4d, 0x78, 0x4d, 0x54, 0x55, 0x34, 0x4e, 0x54, 0x68, 0x61, 0x46, 0x77, 0x30, 0x7a, 0x4d, 0x6a, 0x45, 0x78, 0x4d, 0x44, 0x67, 0x78, 0xa, 0x4d, 0x54, 0x55, 0x34, 0x4e, 0x54, 0x68, 0x61, 0x4d, 0x48, 0x30, 0x78, 0x43, 0x7a, 0x41, 0x4a, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x59, 0x54, 0x41, 0x6b, 0x4e, 0x49, 0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59, 0x44, 0x56, 0x51, 0x51, 0x49, 0x45, 0x77, 0x4a, 0x61, 0x53, 0x44, 0x45, 0x50, 0x4d, 0x41, 0x30, 0x47, 0x41, 0x31, 0x55, 0x45, 0x42, 0x78, 0x4d, 0x47, 0x57, 0x6e, 0x56, 0x79, 0xa, 0x61, 0x57, 0x4e, 0x6f, 0x4d, 0x52, 0x41, 0x77, 0x44, 0x67, 0x59, 0x44, 0x56, 0x51, 0x51, 0x4b, 0x45, 0x77, 0x64, 0x55, 0x61, 0x48, 0x4a, 0x6c, 0x5a, 0x57, 0x31, 0x68, 0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59, 0x44, 0x56, 0x51, 0x51, 0x4c, 0x45, 0x77, 0x4a, 0x44, 0x51, 0x54, 0x45, 0x54, 0x4d, 0x42, 0x45, 0x47, 0x41, 0x31, 0x55, 0x45, 0x41, 0x78, 0x4d, 0x4b, 0x56, 0x47, 0x68, 0x79, 0xa, 0x5a, 0x57, 0x56, 0x74, 0x59, 0x53, 0x42, 0x44, 0x51, 0x54, 0x45, 0x63, 0x4d, 0x42, 0x6f, 0x47, 0x43, 0x53, 0x71, 0x47, 0x53, 0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x4a, 0x41, 0x52, 0x59, 0x4e, 0x59, 0x32, 0x46, 0x41, 0x64, 0x47, 0x68, 0x79, 0x5a, 0x57, 0x56, 0x74, 0x59, 0x53, 0x35, 0x6a, 0x61, 0x44, 0x43, 0x43, 0x41, 0x53, 0x49, 0x77, 0x44, 0x51, 0x59, 0x4a, 0x4b, 0x6f, 0x5a, 0x49, 0xa, 0x68, 0x76, 0x63, 0x4e, 0x41, 0x51, 0x45, 0x42, 0x42, 0x51, 0x41, 0x44, 0x67, 0x67, 0x45, 0x50, 0x41, 0x44, 0x43, 0x43, 0x41, 0x51, 0x6f, 0x43, 0x67, 0x67, 0x45, 0x42, 0x41, 0x4b, 0x38, 0x47, 0x64, 0x6f, 0x54, 0x37, 0x49, 0x70, 0x4e, 0x43, 0x33, 0x44, 0x7a, 0x37, 0x49, 0x55, 0x47, 0x59, 0x57, 0x39, 0x70, 0x4f, 0x42, 0x77, 0x78, 0x2b, 0x39, 0x45, 0x6e, 0x44, 0x5a, 0x72, 0x6b, 0x4e, 0xa, 0x56, 0x44, 0x38, 0x6c, 0x33, 0x4b, 0x66, 0x42, 0x48, 0x6a, 0x47, 0x54, 0x64, 0x69, 0x39, 0x67, 0x51, 0x36, 0x4e, 0x68, 0x2b, 0x6d, 0x51, 0x39, 0x2f, 0x79, 0x51, 0x38, 0x32, 0x35, 0x34, 0x54, 0x32, 0x62, 0x69, 0x67, 0x39, 0x70, 0x30, 0x68, 0x63, 0x6e, 0x38, 0x6b, 0x6a, 0x67, 0x45, 0x51, 0x67, 0x4a, 0x57, 0x48, 0x70, 0x4e, 0x68, 0x59, 0x6e, 0x4f, 0x68, 0x79, 0x33, 0x69, 0x30, 0x6a, 0xa, 0x63, 0x6d, 0x6c, 0x7a, 0x62, 0x31, 0x4d, 0x46, 0x2f, 0x64, 0x65, 0x46, 0x6a, 0x4a, 0x56, 0x74, 0x75, 0x4d, 0x50, 0x33, 0x74, 0x71, 0x54, 0x77, 0x69, 0x4d, 0x61, 0x76, 0x70, 0x77, 0x65, 0x6f, 0x61, 0x32, 0x30, 0x6c, 0x47, 0x44, 0x6e, 0x2f, 0x43, 0x4c, 0x5a, 0x6f, 0x64, 0x75, 0x30, 0x52, 0x61, 0x38, 0x6f, 0x4c, 0x37, 0x38, 0x62, 0x36, 0x46, 0x56, 0x7a, 0x74, 0x4e, 0x6b, 0x57, 0x67, 0xa, 0x50, 0x64, 0x69, 0x57, 0x43, 0x6c, 0x4d, 0x6b, 0x30, 0x4a, 0x50, 0x50, 0x4d, 0x6c, 0x66, 0x4c, 0x45, 0x69, 0x4b, 0x38, 0x68, 0x66, 0x48, 0x45, 0x2b, 0x36, 0x6d, 0x52, 0x56, 0x58, 0x6d, 0x69, 0x31, 0x32, 0x69, 0x74, 0x4b, 0x31, 0x73, 0x65, 0x6d, 0x6d, 0x77, 0x79, 0x48, 0x4b, 0x64, 0x6a, 0x39, 0x66, 0x47, 0x34, 0x58, 0x39, 0x2b, 0x72, 0x51, 0x32, 0x73, 0x4b, 0x75, 0x4c, 0x66, 0x65, 0xa, 0x6a, 0x78, 0x37, 0x75, 0x46, 0x78, 0x6e, 0x41, 0x46, 0x2b, 0x47, 0x69, 0x76, 0x43, 0x75, 0x43, 0x6f, 0x38, 0x78, 0x66, 0x4f, 0x65, 0x73, 0x4c, 0x77, 0x37, 0x32, 0x76, 0x78, 0x2b, 0x57, 0x37, 0x6d, 0x6d, 0x64, 0x59, 0x73, 0x68, 0x67, 0x2f, 0x6c, 0x58, 0x4f, 0x63, 0x71, 0x76, 0x73, 0x7a, 0x51, 0x51, 0x2f, 0x4c, 0x6d, 0x46, 0x45, 0x56, 0x51, 0x59, 0x78, 0x4e, 0x61, 0x65, 0x65, 0x56, 0xa, 0x6e, 0x50, 0x53, 0x41, 0x73, 0x2b, 0x68, 0x74, 0x38, 0x76, 0x55, 0x50, 0x57, 0x34, 0x73, 0x58, 0x39, 0x49, 0x6b, 0x58, 0x4b, 0x56, 0x67, 0x42, 0x4a, 0x64, 0x31, 0x52, 0x31, 0x69, 0x73, 0x55, 0x70, 0x6f, 0x46, 0x36, 0x64, 0x4b, 0x6c, 0x55, 0x65, 0x78, 0x6d, 0x76, 0x4c, 0x78, 0x45, 0x79, 0x66, 0x35, 0x63, 0x43, 0x41, 0x77, 0x45, 0x41, 0x41, 0x61, 0x4f, 0x42, 0x34, 0x7a, 0x43, 0x42, 0xa, 0x34, 0x44, 0x41, 0x64, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x51, 0x34, 0x45, 0x46, 0x67, 0x51, 0x55, 0x77, 0x36, 0x4c, 0x61, 0x43, 0x37, 0x2b, 0x4a, 0x36, 0x32, 0x72, 0x4b, 0x64, 0x61, 0x54, 0x41, 0x33, 0x37, 0x6b, 0x41, 0x59, 0x59, 0x55, 0x62, 0x72, 0x6b, 0x67, 0x77, 0x67, 0x62, 0x41, 0x47, 0x41, 0x31, 0x55, 0x64, 0x49, 0x77, 0x53, 0x42, 0x71, 0x44, 0x43, 0x42, 0x70, 0x59, 0x41, 0x55, 0xa, 0x77, 0x36, 0x4c, 0x61, 0x43, 0x37, 0x2b, 0x4a, 0x36, 0x32, 0x72, 0x4b, 0x64, 0x61, 0x54, 0x41, 0x33, 0x37, 0x6b, 0x41, 0x59, 0x59, 0x55, 0x62, 0x72, 0x6b, 0x69, 0x68, 0x67, 0x59, 0x47, 0x6b, 0x66, 0x7a, 0x42, 0x39, 0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59, 0x44, 0x56, 0x51, 0x51, 0x47, 0x45, 0x77, 0x4a, 0x44, 0x53, 0x44, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47, 0x41, 0x31, 0x55, 0x45, 0xa, 0x43, 0x42, 0x4d, 0x43, 0x57, 0x6b, 0x67, 0x78, 0x44, 0x7a, 0x41, 0x4e, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x63, 0x54, 0x42, 0x6c, 0x70, 0x31, 0x63, 0x6d, 0x6c, 0x6a, 0x61, 0x44, 0x45, 0x51, 0x4d, 0x41, 0x34, 0x47, 0x41, 0x31, 0x55, 0x45, 0x43, 0x68, 0x4d, 0x48, 0x56, 0x47, 0x68, 0x79, 0x5a, 0x57, 0x56, 0x74, 0x59, 0x54, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47, 0x41, 0x31, 0x55, 0x45, 0xa, 0x43, 0x78, 0x4d, 0x43, 0x51, 0x30, 0x45, 0x78, 0x45, 0x7a, 0x41, 0x52, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x4d, 0x54, 0x43, 0x6c, 0x52, 0x6f, 0x63, 0x6d, 0x56, 0x6c, 0x62, 0x57, 0x45, 0x67, 0x51, 0x30, 0x45, 0x78, 0x48, 0x44, 0x41, 0x61, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x43, 0x51, 0x45, 0x57, 0x44, 0x57, 0x4e, 0x68, 0x51, 0x48, 0x52, 0x6f, 0xa, 0x63, 0x6d, 0x56, 0x6c, 0x62, 0x57, 0x45, 0x75, 0x59, 0x32, 0x69, 0x43, 0x43, 0x51, 0x44, 0x4e, 0x51, 0x30, 0x66, 0x77, 0x77, 0x55, 0x52, 0x61, 0x55, 0x44, 0x41, 0x4d, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x52, 0x4d, 0x45, 0x42, 0x54, 0x41, 0x44, 0x41, 0x51, 0x48, 0x2f, 0x4d, 0x41, 0x30, 0x47, 0x43, 0x53, 0x71, 0x47, 0x53, 0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x42, 0x42, 0x51, 0x55, 0x41, 0xa, 0x41, 0x34, 0x49, 0x42, 0x41, 0x51, 0x41, 0x52, 0x48, 0x4d, 0x79, 0x49, 0x48, 0x42, 0x44, 0x46, 0x75, 0x6c, 0x2b, 0x68, 0x76, 0x6a, 0x41, 0x43, 0x74, 0x36, 0x72, 0x30, 0x45, 0x41, 0x48, 0x59, 0x77, 0x52, 0x39, 0x47, 0x51, 0x53, 0x67, 0x68, 0x49, 0x51, 0x73, 0x66, 0x48, 0x74, 0x38, 0x63, 0x79, 0x56, 0x63, 0x7a, 0x6d, 0x45, 0x6e, 0x4a, 0x48, 0x39, 0x68, 0x72, 0x76, 0x68, 0x39, 0x51, 0xa, 0x56, 0x69, 0x76, 0x6d, 0x37, 0x6d, 0x72, 0x66, 0x76, 0x65, 0x69, 0x68, 0x6d, 0x4e, 0x58, 0x41, 0x6e, 0x34, 0x57, 0x6c, 0x47, 0x77, 0x51, 0x2b, 0x41, 0x43, 0x75, 0x56, 0x74, 0x54, 0x4c, 0x78, 0x77, 0x38, 0x45, 0x72, 0x62, 0x53, 0x54, 0x37, 0x49, 0x4d, 0x41, 0x4f, 0x78, 0x39, 0x6e, 0x70, 0x48, 0x66, 0x2f, 0x6b, 0x6e, 0x67, 0x6e, 0x5a, 0x34, 0x6e, 0x53, 0x77, 0x55, 0x52, 0x46, 0x39, 0xa, 0x72, 0x43, 0x45, 0x79, 0x48, 0x71, 0x31, 0x37, 0x39, 0x70, 0x4e, 0x58, 0x70, 0x4f, 0x7a, 0x5a, 0x32, 0x35, 0x37, 0x45, 0x35, 0x72, 0x30, 0x61, 0x76, 0x4d, 0x4e, 0x4e, 0x58, 0x58, 0x44, 0x77, 0x75, 0x6c, 0x77, 0x30, 0x33, 0x69, 0x42, 0x45, 0x32, 0x31, 0x65, 0x62, 0x64, 0x30, 0x30, 0x70, 0x47, 0x31, 0x31, 0x47, 0x56, 0x71, 0x2f, 0x49, 0x32, 0x36, 0x73, 0x2b, 0x38, 0x42, 0x6a, 0x6e, 0xa, 0x44, 0x4b, 0x52, 0x50, 0x71, 0x75, 0x4b, 0x72, 0x53, 0x4f, 0x34, 0x2f, 0x6c, 0x75, 0x45, 0x44, 0x76, 0x4c, 0x34, 0x6e, 0x67, 0x69, 0x51, 0x6a, 0x5a, 0x70, 0x33, 0x32, 0x53, 0x39, 0x5a, 0x31, 0x4b, 0x39, 0x73, 0x56, 0x4f, 0x7a, 0x71, 0x74, 0x51, 0x37, 0x49, 0x39, 0x7a, 0x7a, 0x65, 0x55, 0x41, 0x44, 0x6d, 0x33, 0x61, 0x56, 0x61, 0x2f, 0x42, 0x70, 0x61, 0x77, 0x34, 0x69, 0x4d, 0x52, 0xa, 0x31, 0x53, 0x49, 0x37, 0x6f, 0x39, 0x61, 0x4a, 0x59, 0x69, 0x52, 0x69, 0x31, 0x67, 0x78, 0x59, 0x50, 0x32, 0x42, 0x55, 0x41, 0x31, 0x49, 0x46, 0x71, 0x72, 0x38, 0x4e, 0x7a, 0x79, 0x66, 0x47, 0x44, 0x37, 0x74, 0x52, 0x48, 0x64, 0x71, 0x37, 0x62, 0x5a, 0x4f, 0x78, 0x58, 0x41, 0x6c, 0x75, 0x76, 0x38, 0x31, 0x64, 0x63, 0x62, 0x7a, 0x30, 0x53, 0x42, 0x58, 0x38, 0x53, 0x67, 0x56, 0x31, 0xa, 0x34, 0x48, 0x45, 0x4b, 0x63, 0x36, 0x78, 0x4d, 0x41, 0x4e, 0x6e, 0x59, 0x73, 0x2f, 0x61, 0x59, 0x4b, 0x6a, 0x76, 0x6d, 0x50, 0x30, 0x56, 0x70, 0x4f, 0x76, 0x52, 0x55, 0xa, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0xa}

// uploadBlob Uploads a blob to the threema servers and returns the assigned blob ID
func uploadBlob(blob []byte) ([16]byte, error) {
	CAPool := x509.NewCertPool()
	CAPool.AppendCertsFromPEM(threemaCert)

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
		return [16]byte{}, errors.New("could not load server certificate")
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
func encryptAsymAndUpload(sc SessionContext, plainImage []byte, recipientName string) (blobNonce nonce, ServerID byte, size uint32, blobID [16]byte, err error) {
	// Get contact public key
	threemaID := sc.ID
	recipient, inContacts := threemaID.Contacts.Get(recipientName)
	if !inContacts {
		var tr ThreemaRest
		recipient, err = tr.GetContactByID(NewIDString(recipientName))
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

// encryptSymAndUpload encrypts a blob with recipients PK and the sc owners SK
func encryptSymAndUpload(plainImage []byte) (key [32]byte, ServerID byte, size uint32, blobID [16]byte, err error) {
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
	CAPool := x509.NewCertPool()
	CAPool.AppendCertsFromPEM(threemaCert)

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
		sender, err = tr.GetContactByID(NewIDString(senderName))
		if err != nil {
			return []byte{}, err
		}
	}

	plainPicture, success := box.Open(nil, ciphertext, blobNonce.bytes(), &sender.LPK, &threemaID.LSK)
	if !success {
		return []byte{}, errors.New("could not decrypt image message")
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
		return []byte{}, errors.New("could not decrypt image message")
	}

	return plainPicture, nil
}
