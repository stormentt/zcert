package auth

import (
	"crypto/subtle"
	"encoding/hex"

	"github.com/spf13/viper"
	"golang.org/x/crypto/blake2b"

	log "github.com/sirupsen/logrus"
)

const HMACLength = 32 // 256 / 8

func CheckHMAC(expectedHMAC []byte, body []byte) (bool, error) {
	calcHMAC, err := CalcHMAC(body)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare(calcHMAC, expectedHMAC) != 1 { // not equal
		log.WithFields(log.Fields{
			"calcHMAC":     hex.EncodeToString(calcHMAC),
			"expectedHMAC": hex.EncodeToString(expectedHMAC),
		}).Debug("hmac mismatch")

		return false, nil
	}

	return true, nil
}

func CalcHMAC(body []byte) ([]byte, error) {
	authkey := viper.GetString("authkey")

	b2, err := blake2b.New256([]byte(authkey))
	if err != nil {
		return nil, err
	}

	b2.Write(body)
	return b2.Sum(nil), nil
}
