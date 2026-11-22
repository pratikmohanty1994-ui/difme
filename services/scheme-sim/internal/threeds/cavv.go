// Package threeds holds what the ACS and the authorisation switch share for EMV 3-D Secure (ADR-027): the CAVV layout
// and the security-module client that computes and checks its cryptographic part.
//
// CAVV (authenticationValue, 20 bytes, base64 on the wire; DIFME layout modelled on Visa's CVV-with-ATN method):
//
//	[0]     usage/version   0x07
//	[1]     authentication result code: 1 challenge passed, 2 frictionless (risk-based), 3 network token (TAVV),
//	        7 attempt (stand-in)
//	[2]     second-factor result code (BCD): 00 none, 01 OTP
//	[3]     CAVV key indicator (selects the CVK; 01 today) so keys rotate without breaking in-flight authentications
//	[4:6]   CVV output, 3 digits BCD (0x0675 = "675"), from the security module
//	[6:8]   unpredictable number: the last 4 digits of the ATN, BCD (binds the ATN into the cryptogram)
//	[8:12]  ATN, authentication tracking number (big-endian); unique per card, so a CAVV is accepted once
//	[12]    ECI: 05 authenticated, 06 attempt, 07 network token payment (TAVV)
//	[13:20] zero
//
// Like Visa's CVV-method CAVV it does not bind amount or merchant: the switch checks those against the
// authentication record where it has one.
package threeds

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Usage           = 0x07
	ResultChallenge = 1
	ResultFriction  = 2 // frictionless
	ResultToken     = 3 // network token cryptogram (TAVV, ADR-024): token presented by its requestor
	ResultAttempt   = 7
	KeyIndicator    = 0x01
)

type CAVV struct {
	Result       int    // authentication result code
	SecondFactor int    // 0 none, 1 OTP
	KeyIndicator int    // CVK selector
	CVV          string // 3 digits
	ATN          uint32
	ECI          int
}

// UPN is the unpredictable number fed to the CVV algorithm: the ATN's last 4 digits.
func (c CAVV) UPN() string { return fmt.Sprintf("%04d", c.ATN%10000) }

func (c CAVV) AuthRC() string { return fmt.Sprintf("%d", c.Result) }
func (c CAVV) SFARC() string  { return fmt.Sprintf("%02d", c.SecondFactor) }

// ECIFor returns the ECI an authentication result must carry.
func ECIFor(result int) int {
	switch result {
	case ResultAttempt:
		return 6
	case ResultToken:
		return 7
	}
	return 5
}

func bcd(s string) []byte {
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b := make([]byte, len(s)/2)
	for i := range b {
		b[i] = (s[2*i]-'0')<<4 | (s[2*i+1] - '0')
	}
	return b
}

func unbcd(b []byte) (string, error) {
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		hi, lo := x>>4, x&0x0f
		if hi > 9 || lo > 9 {
			return "", errors.New("not BCD")
		}
		out = append(out, '0'+hi, '0'+lo)
	}
	return string(out), nil
}

// Encode returns the base64 authenticationValue.
func (c CAVV) Encode() string {
	b := make([]byte, 20)
	b[0], b[1], b[3] = Usage, byte(c.Result), byte(c.KeyIndicator)
	copy(b[2:3], bcd(fmt.Sprintf("%02d", c.SecondFactor)))
	copy(b[4:6], bcd(c.CVV))
	copy(b[6:8], bcd(c.UPN()))
	binary.BigEndian.PutUint32(b[8:12], c.ATN)
	b[12] = byte(c.ECI)
	return base64.StdEncoding.EncodeToString(b)
}

var ErrFormat = errors.New("CAVV format")

// Decode parses an authenticationValue and checks its internal consistency (not its cryptogram).
func Decode(s string) (CAVV, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 20 || b[0] != Usage {
		return CAVV{}, ErrFormat
	}
	for _, z := range b[13:] {
		if z != 0 {
			return CAVV{}, ErrFormat
		}
	}
	sf, err1 := unbcd(b[2:3])
	cvv, err2 := unbcd(b[4:6])
	upn, err3 := unbcd(b[6:8])
	if err1 != nil || err2 != nil || err3 != nil || cvv[0] != '0' {
		return CAVV{}, ErrFormat
	}
	c := CAVV{Result: int(b[1]), KeyIndicator: int(b[3]), CVV: cvv[1:], ATN: binary.BigEndian.Uint32(b[8:12]), ECI: int(b[12])}
	fmt.Sscanf(sf, "%d", &c.SecondFactor)
	if upn != c.UPN() || (c.Result != ResultChallenge && c.Result != ResultFriction && c.Result != ResultToken && c.Result != ResultAttempt) || c.ECI != ECIFor(c.Result) {
		return CAVV{}, ErrFormat
	}
	return c, nil
}

// NewATN returns a random authentication tracking number.
func NewATN() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
