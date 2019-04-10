package encode

import (
	"encoding/base64"
)

func Base64Encode(in []byte) (out []byte) {
	l := base64.StdEncoding.EncodedLen(len(in))
	out = make([]byte, l)
	base64.StdEncoding.Encode(out, in)
	return
}

func Base64Decode(in []byte) (out []byte, err error) {
	l := base64.StdEncoding.DecodedLen(len(in))
	s := make([]byte, l)
	n, err := base64.StdEncoding.Decode(s, in)
	if err != nil {
		return nil, err
	}
	return s[:n], err
}
