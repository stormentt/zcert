package server

import (
	"io/ioutil"
	"time"

	"net/http"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zcert/util"
)

type signCertReq struct {
	CSR      string        `json:"csr"`
	Duration time.Duration `json:"duration"`
}

func signCert(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to read certificate from http body")

		c.String(http.StatusInternalServerError, "internal server error")
		return
	}

	var req signCertReq
	if err = c.BindJSON(&req); err != nil {
		c.String(http.StatusBadRequest, "invalid sign-csr json")
		return
	}

	csrBytes, err := util.DecodeB64(req.CSR)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid sign-csr base64")
		return
	}

	log.WithFields(log.Fields{
		"body":     len(body),
		"csrBytes": len(csrBytes),
	}).Info("got sign-csr request")
}
