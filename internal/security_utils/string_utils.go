// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ---------------------------------------------------
// String Utils
// ---------------------------------------------------
func CaseInsensitiveEquals(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return s == substr
}

func GetSubString(data string, i, j int) string {
	if i < 0 {
		i = 0
	}
	if j >= len(data) {
		j = len(data) - 1
	}
	return data[i:j]

}
func CaseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}

func ContainsInArray(s []string, substr string) bool {
	for arr := range s {
		if strings.Contains(substr, s[arr]) {
			return true
		}
	}
	return false
}

func StartWithInArray(s []string, substr string) bool {
	for arr := range s {
		if strings.HasPrefix(substr, s[arr]) {
			return true
		}
	}
	return false
}

func CheckGrpcByte(a [][]byte, b []byte) bool {
	for x := range a {
		// In Grpc Handling first 5 bytes used to identify length of data stream.
		tmp := a[x]
		if len(tmp) > 5 {
			tmp = tmp[5:]
		}
		if checkbyte(tmp, b) {
			return true
		}

	}
	return false
}

func checkbyte(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func MapToString(mapdata map[string]interface{}) string {
	str := ""
	for i, j := range mapdata {
		str = str + i + ": " + fmt.Sprintf("%v", j) + "\n"
	}
	return str
}

func EscapeString(q string) string {
	r := q
	r = strings.Replace(r, "\"", "\\\"", -1)
	r = strings.Replace(r, "\r", "\\r", -1)
	r = strings.Replace(r, "\n", "\\n", -1)
	return r

}

func StringSHA256(f string) string {
	sum := sha256.Sum256([]byte(f))
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return string(dst)
}

func IsBlank(in string) bool {
	return in == ""
}

func IsAnyBlank(stringSequence ...string) bool {
	for in := range stringSequence {
		if IsBlank(stringSequence[in]) {
			return true
		}
	}
	return false
}
