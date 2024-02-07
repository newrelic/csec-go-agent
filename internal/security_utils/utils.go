// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: New Relic Software License v1.0

package security_utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/build"
	"math"
	"net/url"

	"io/ioutil"
	"net"
	"os"
	"path/filepath"
)

// ---------------------------------------------------
// Basic Utils
// ---------------------------------------------------

func FindIpAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func GetUniqueUUID() (uuid string) {
	//https://stackoverflow.com/questions/15130321/is-there-a-method-to-generate-a-uuid-with-go-language
	//https://github.com/google/uuid
	buffer := make([]byte, 16)
	_, err := rand.Read(buffer)
	if err != nil {
		return string(buffer)
	}
	buffer[6] = (buffer[6] & 0x0f) | 0x40 // Version 4
	buffer[8] = (buffer[8] & 0x3f) | 0x80 // Variant is 10

	var buf [36]byte
	encodeHex(buf[:], buffer)
	return string(buf[:])
}

func encodeHex(dst []byte, uuid []byte) {
	hex.Encode(dst, uuid[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], uuid[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], uuid[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], uuid[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], uuid[10:])
}

// ---------------------------------------------------
// Func: CalculateSha256 - compure sha256
// ---------------------------------------------------
func CalculateSha256(f string) string {
	b, e := ioutil.ReadFile(f)
	if e != nil {
		return "ERROR"
	}
	sum := sha256.Sum256(b)
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return string(dst)
}

// ---------------------------------------------------
// Func: CalculateSha256 - compure sha256
// ---------------------------------------------------

func IsFileExist(file string) bool {
	if _, err := os.Stat(file); err == nil {
		return true
	} else {
		return false
	}
}

// ---------------------------------------------------
// Func validJSON - basic check format matches JSON
// ---------------------------------------------------
func ValidJSON(j string) bool {
	var checkJ map[string]interface{}
	if err := json.Unmarshal([]byte(j), &checkJ); err != nil {
		return false
	}
	return true
}

func GetCurrentWorkingDir() string {
	w, _ := filepath.Abs(".")
	if w1, e1 := os.Getwd(); e1 != nil {
		w, _ = filepath.Abs(w1)
		if wi, e := os.Lstat(w); (e == nil) && (wi.Mode()&os.ModeSymlink != 0) {
			if wx, e2 := os.Readlink(w); e2 != nil {
				w, _ = filepath.Abs(wx)
			}
		}
	}
	w, _ = filepath.Abs(w)
	return w
}

func GetGoPath() string {
	path := os.Getenv("GOPATH")
	if path == "" {
		path = build.Default.GOPATH
	}
	return path
}
func GetGoRoot() string {
	path := os.Getenv("GOROOT")
	if path == "" {
		path = build.Default.GOPATH
	}
	return path
}

func CalculateFileSize(path string) string {
	fi, k2e2 := os.Stat(path)
	if k2e2 != nil {
		return "-1"
	} else {
		return getSize(fi.Size())
	}
}

func StructToString(data interface{}) string {
	json, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(json)
}

func getSize(size int64) string {
	var suffixes = [8]string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"}

	size1 := (float64)(size)
	base := math.Log(size1) / math.Log(1024)
	getSize := fmt.Sprintf("%.2f", math.Pow(1024, base-math.Floor(base)))
	index := int(math.Floor(base))
	if index > 7 {
		index = 7
	}
	getSuffix := suffixes[index]
	return getSize + " " + string(getSuffix)
}

// CanonicalURL removed all encoded query values from request URL
func CanonicalURL(urlx string) string {
	u, err := url.Parse(urlx)
	if err != nil {
		return urlx
	}
	u.RawQuery = ""
	updatedURL := u.String()
	if updatedURL == "" {
		return urlx
	}
	return updatedURL
}

func Contains(ports []int, port int) bool {
	for _, a := range ports {
		if a == port {
			return true
		}
	}
	return false
}
