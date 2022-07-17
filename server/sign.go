package server

import (
	"bytes"
	"fmt"
	"time"

	"net/http"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zcert/apitypes"
	"github.com/stormentt/zcert/auth"
	"github.com/stormentt/zcert/certs"
	"github.com/stormentt/zcert/util"
)

func signCert(c *gin.Context) {
	var req apitypes.SignCertReq
	if err := c.BindJSON(&req); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Debug("invalid sign-csr json")

		c.String(http.StatusBadRequest, "invalid sign-csr json")
		return
	}

	if req.Nonce == "" {
		c.String(http.StatusBadRequest, "no nonce in json")
		return
	}

	if len(req.Nonce) > 32 {
		c.String(http.StatusBadRequest, "nonce too long. nonce must be at most 32 characters")
		return
	}

	if req.RequestTime.IsZero() {
		c.String(http.StatusBadRequest, "bad request_time in json")
		return
	}

	if time.Since(req.RequestTime) > time.Minute {
		c.String(http.StatusBadRequest, fmt.Sprintf("request_time too old (%s ago)", time.Since(req.RequestTime)))
		return
	}

	if noncemanager.Seen(req.Nonce) {
		c.String(http.StatusUnauthorized, "nonce reused")
		return
	}
	noncemanager.Record(req.Nonce)

	parsedCSR, err := certs.ParseCSR(req.CSR)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Debug("invalid csr base64")

		c.String(http.StatusBadRequest, "invalid csr base64")
		return
	}

	if err = certs.ValidateCSR(parsedCSR); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Debug("csr signature invalid")

		c.String(http.StatusBadRequest, "csr signature invalid")
		return
	}

	signedCSR, err := certs.SignCSR(parsedCSR, req.Params)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to sign csr")

		c.String(http.StatusInternalServerError, "internal server error")

		return
	}

	buf := bytes.NewBuffer(signedCSR)
	calcHMAC, err := auth.CalcHMAC(buf.Bytes())
	c.Header("Content-HMAC", util.EncodeB64(calcHMAC))
	c.DataFromReader(http.StatusOK, int64(buf.Len()), "application/x-x509-user-cert", buf, nil)
}
