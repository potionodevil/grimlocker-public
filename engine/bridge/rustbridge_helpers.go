package bridge

import (
	"encoding/base64"
	"fmt"
)

func EncodeOffsetsJSON(offsets []int64) string {
	buf := make([]byte, 0, len(offsets)*12+2)
	buf = append(buf, '[')
	for i, o := range offsets {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, fmt.Sprintf("%d", o)...)
	}
	buf = append(buf, ']')
	return string(buf)
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
