package simple_otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"time"
)

type TotpAlgo int

const (
	TotpNotSpecified TotpAlgo = 0
	TotpSha1         TotpAlgo = 1
	TotpSha256       TotpAlgo = 2
	TotpSha512       TotpAlgo = 3
)

// Time-based One-Time Password from RFC - https://datatracker.ietf.org/doc/html/rfc6238
type TOTP struct {
	Secret    string   // Secret key (required)
	Digits    int      // OTP digit count (default: 6)
	Algorithm TotpAlgo // OTP Algorithm ("SHA1" or "SHA256" or "SHA512") (default: SHA1)
	Period    int64    // Period for which OTP is valid (seconds) (default: 30)
	UnixTime  int64    // (Optional) Unix Timestamp (default: Current unix timestamp)
}

// Generate TOTP code and returns OTP as string and any error encountered.
func (t *TOTP) Generate() (string, error) {
	Zero := int64(0)
	currentUnixTime := int64(0)

	if len(t.Secret) == 0 {
		return "", fmt.Errorf("no secret key provided")
	}

	if t.Digits == 0 {
		t.Digits = 6
	}

	if t.Algorithm == TotpNotSpecified {
		t.Algorithm = TotpSha256
	}

	if t.Period == 0 {
		t.Period = 30
	}

	if t.UnixTime != 0 {
		currentUnixTime = t.UnixTime
	} else {
		currentUnixTime = time.Now().Unix() - Zero
	}

	currentUnixTime /= t.Period

	return generateOTP(t.Secret, currentUnixTime, t.Digits, t.Algorithm)
}

// function for generating TOTP codes
func generateOTP(base32Key string, counter int64, digits int, algo TotpAlgo) (string, error) {
	var initialHMAC hash.Hash
	bytesCounter := make([]byte, 8)
	binary.BigEndian.PutUint64(bytesCounter, uint64(counter)) // convert counter to byte array

	secretKey, err := base32.StdEncoding.DecodeString(base32Key) // decode base32 secret to byte array
	if err != nil {
		return "", fmt.Errorf("bad secret key : %q", base32Key)
	}

	switch algo {
	case TotpSha1:
		initialHMAC = hmac.New(sha1.New, secretKey)
	case TotpSha256:
		initialHMAC = hmac.New(sha256.New, secretKey)
	case TotpSha512:
		initialHMAC = hmac.New(sha512.New, secretKey)
	default:
		return "", fmt.Errorf("invalid algorithm - provide one of SHA1/SHA256/SHA512")
	}

	_, err = initialHMAC.Write(bytesCounter)
	if err != nil {
		return "", fmt.Errorf("unable to compute HMAC")
	}

	hashHMAC := initialHMAC.Sum(nil)
	offset := hashHMAC[len(hashHMAC)-1] & 0xF
	hashHMAC = hashHMAC[offset : offset+4]

	hashHMAC[0] = hashHMAC[0] & 0x7F
	decimal := binary.BigEndian.Uint32(hashHMAC)
	otp := decimal % uint32(math.Pow10(digits))

	result := strconv.Itoa(int(otp))
	for len(result) != digits {
		result = "0" + result
	}

	return result, nil
}
