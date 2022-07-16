package server

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/stormentt/zcert/auth"
	"github.com/stormentt/zcert/util"

	log "github.com/sirupsen/logrus"
)

func getCA(c *gin.Context) {
	buf := new(bytes.Buffer)
	err := util.EncodeX509Cert(buf, CaCert.Raw)

	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("unable to encode CACert")

		c.String(http.StatusInternalServerError, "internal server error")

		return
	}

	calcHMAC, err := auth.CalcHMAC(buf.Bytes())
	c.Header("X-HMAC", util.EncodeB64(calcHMAC))
	c.DataFromReader(http.StatusOK, int64(buf.Len()), "application/x-x509-ca-cert", buf, nil)
}
