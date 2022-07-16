package middleware

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/stormentt/zcert/auth"

	log "github.com/sirupsen/logrus"
)

func CheckAuth(c *gin.Context) {
	expectedHMAC, err := auth.GetHMACFromHeader(c)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Debug("invalid X-HMAC header")

		c.String(http.StatusBadRequest, "invalid X-HMAC header")
		c.Abort()
		return
	}

	bodyBytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to read HTTP body")

		c.String(http.StatusInternalServerError, "internal server error")
		c.Abort()
		return
	}

	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	match, err := auth.CheckHMAC(expectedHMAC, bodyBytes)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to check HMAC")

		c.String(http.StatusInternalServerError, "internal server error")
		c.Abort()
		return
	}

	if !match {
		c.String(http.StatusUnauthorized, "X-HMAC header does not match computed HMAC")
		c.Abort()
		return
	}

	c.Next()
}
