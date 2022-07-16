package server

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/stormentt/zcert/util"
)

func getCA(c *gin.Context) {
	buf := new(bytes.Buffer)
	err := util.EncodeX509Cert(buf, CaCert.Raw)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})

		return
	}

	util.AuthorizedResp(c, gin.H{
		"ca": util.EncodeB64(buf.Bytes()),
	})
}
