// Copyright 2017 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

// RandID return a rand string used in frp.
func RandID() (id string, err error) {
	return RandIDWithLen(8)
}

// RandIDWithLen return a rand string with idLen length.
func RandIDWithLen(idLen int) (id string, err error) {
	b := make([]byte, idLen)
	_, err = rand.Read(b)
	if err != nil {
		return
	}

	id = fmt.Sprintf("%x", b)
	return
}

func GetAuthKey(token string, timestamp int64) (key string) {
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(token))
	md5Ctx.Write([]byte(strconv.FormatInt(timestamp, 10)))
	data := md5Ctx.Sum(nil)
	return hex.EncodeToString(data)
}

func CanonicalAddr(host string, port int) (addr string) {
	if port == 80 || port == 443 {
		addr = host
	} else {
		addr = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return
}

func ParseRangeNumbers(rangeStr string) (numbers []int64, err error) {
	rangeStr = strings.TrimSpace(rangeStr)
	numbers = make([]int64, 0)
	// e.g. 1000-2000,2001,2002,3000-4000
	numRanges := strings.Split(rangeStr, ",")
	for _, numRangeStr := range numRanges {
		// 1000-2000 or 2001
		numArray := strings.Split(numRangeStr, "-")
		// length: only 1 or 2 is correct
		rangeType := len(numArray)
		switch rangeType {
		case 1:
			// single number
			singleNum, errRet := strconv.ParseInt(strings.TrimSpace(numArray[0]), 10, 64)
			if errRet != nil {
				err = fmt.Errorf("range number is invalid, %v", errRet)
				return
			}
			numbers = append(numbers, singleNum)
		case 2:
			// range numbers
			min, errRet := strconv.ParseInt(strings.TrimSpace(numArray[0]), 10, 64)
			if errRet != nil {
				err = fmt.Errorf("range number is invalid, %v", errRet)
				return
			}
			max, errRet := strconv.ParseInt(strings.TrimSpace(numArray[1]), 10, 64)
			if errRet != nil {
				err = fmt.Errorf("range number is invalid, %v", errRet)
				return
			}
			if max < min {
				err = fmt.Errorf("range number is invalid")
				return
			}
			for i := min; i <= max; i++ {
				numbers = append(numbers, i)
			}
		default:
			err = fmt.Errorf("range number is invalid")
			return
		}
	}
	return
}

func GenerateResponseErrorString(summary string, err error, detailed bool) string {
	if detailed {
		return err.Error()
	}
	return summary
}

func RandomSleep(duration time.Duration, minRatio, maxRatio float64) time.Duration {
	min := int64(minRatio * 1000.0)
	max := int64(maxRatio * 1000.0)
	var n int64
	if max <= min {
		n = min
	} else {
		n = mathrand.Int63n(max-min) + min
	}
	d := duration * time.Duration(n) / time.Duration(1000)
	time.Sleep(d)
	return d
}

func LoadX509KeyPair(certBase64, keyBase64 string) (tls.Certificate, error) {
	if certBase64 == "" || keyBase64 == "" {
		return tls.Certificate{}, fmt.Errorf("no tls certif")
	}
	crt, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(crt, key)
}

func LoadX509KeyPairs(crtBase64, keyBase64 string) ([]tls.Certificate, error) {
	crts, err := SplitTlsCert(crtBase64, keyBase64)
	if err != nil {
		return nil, err
	}

	var certs []tls.Certificate
	for _, crt := range crts {
		cert, err := LoadX509KeyPair(crt[0], crt[1])
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func SplitTlsCert(crtBase64, keyBase64 string) ([][2]string, error) {
	crts := strings.Split(crtBase64, ",")
	keys := strings.Split(keyBase64, ",")
	if len(crts) != len(keys) {
		return nil, fmt.Errorf("tls cert key num error")
	}

	var certs [][2]string
	for i := 0; i < len(crts); i++ {
		certs = append(certs, [2]string{strings.TrimSpace(crts[i]), strings.TrimSpace(keys[i])})
	}
	return certs, nil
}
