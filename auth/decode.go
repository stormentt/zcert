package auth

import (
	"fmt"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zcert/util"
)

type NoHMACError struct{}
type InvalidHMACLengthError struct{}

func (e *NoHMACError) Error() string {
	return "no HMAC provided in Content-HMAC header"
}

func (e *InvalidHMACLengthError) Error() string {
	return fmt.Sprintf("invalid HMAC length, HMAC must be %d bytes long", HMACLength)
}

func GetHMACFromHeader(c *gin.Context) ([]byte, error) {
	encodedHMAC := c.GetHeader("Content-HMAC")
	if len(encodedHMAC) == 0 {
		return nil, &NoHMACError{}
	}

	decodedHMAC, err := util.DecodeB64(encodedHMAC)
	if err != nil {
		return nil, err
	}

	if len(decodedHMAC) != HMACLength {
		log.WithFields(log.Fields{
			"expected": HMACLength,
			"actual":   len(decodedHMAC),
		}).Trace("GetHMACFromHeader: invalid length")

		return nil, &InvalidHMACLengthError{}
	}

	return decodedHMAC, nil
}
