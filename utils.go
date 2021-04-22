package dbgrab

import (
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"time"
)

var matchRe2 = regexp.MustCompile(`\\([^\\])`)
var matchRe = regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)

func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func grabResponse(address string, data []byte, readTimeout time.Duration, writeTimeout time.Duration, ssl bool) ([]byte, error) {
	switch ssl {
	case true:
		return grabWithSSL(address, data, readTimeout, writeTimeout)
	default:
		return grabWithoutSSL(address, data, readTimeout, writeTimeout)
	}
}

func grabWithSSL(address string, data []byte, readTimeout time.Duration, writeTimeout time.Duration) ([]byte, error) {
	var response []byte
	var err error
	conf := &tls.Config{
		Rand:                        nil,
		Time:                        nil,
		Certificates:                nil,
		NameToCertificate:           nil,
		GetCertificate:              nil,
		GetClientCertificate:        nil,
		GetConfigForClient:          nil,
		VerifyPeerCertificate:       nil,
		RootCAs:                     nil,
		NextProtos:                  nil,
		ServerName:                  "",
		ClientAuth:                  0,
		ClientCAs:                   nil,
		InsecureSkipVerify:          true,
		CipherSuites:                nil,
		PreferServerCipherSuites:    false,
		SessionTicketsDisabled:      false,
		SessionTicketKey:            [32]byte{},
		ClientSessionCache:          nil,
		MinVersion:                  0,
		MaxVersion:                  0,
		CurvePreferences:            nil,
		DynamicRecordSizingDisabled: false,
		Renegotiation:               0,
		KeyLogWriter:                nil,
	}

	conn, _ := tls.DialWithDialer(&net.Dialer{
		Timeout:       10 * time.Second,
		LocalAddr:     nil,
		DualStack:     false,
		FallbackDelay: 0,
		KeepAlive:     0,
		Resolver:      nil,
		Cancel:        nil,
		Control:       nil,
	}, "tcp", address, conf)

	if conn == nil {
		return response, err
	}

	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	_, errWrite := conn.Write(data)
	if errWrite != nil {
		return response, errWrite
	}

	err = conn.SetReadDeadline(time.Now().Add(readTimeout))
	if err != nil {
		return response, err
	}
	response, err = ioutil.ReadAll(io.LimitReader(conn, 1024))

	return response, err
}

func grabWithoutSSL(address string, data []byte, readTimeout time.Duration, writeTimeout time.Duration) ([]byte, error) {
	var response []byte
	var err error
	dialer := net.Dialer{
		Timeout:       5 * time.Second,
		LocalAddr:     nil,
		FallbackDelay: 0,
		KeepAlive:     0,
		Resolver:      nil,
		Control:       nil,
	}

	conn, err := dialer.Dial("tcp", address)

	if conn == nil {
		return response, errors.New("Closed")
	}

	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, errWrite := conn.Write(data)
	if errWrite != nil {
		return response, errWrite
	}

	err = conn.SetReadDeadline(time.Now().Add(readTimeout))
	if err != nil {
		return response, err
	}

	response, err = ioutil.ReadAll(io.LimitReader(conn, 1024))

	return response, err
}