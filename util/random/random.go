package random

import (
	"crypto/rand"
	"math/big"

	log "github.com/sirupsen/logrus"
)

// Int returns a random integer between [0, max)
func Int(max int) int {
	bigMax := big.NewInt(int64(max))
	randInt, err := rand.Int(rand.Reader, bigMax)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("error generating random int")
	}
	return int(randInt.Int64())
}

// AlphaNum returns a mixed-case alphanumeric string of the specified length
func AlphaNum(length int) string {
	alphanumeric := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	alphaLen := len(alphanumeric)

	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		letter := Int(alphaLen)
		ret[i] = alphanumeric[letter]
	}

	return string(ret)
}
