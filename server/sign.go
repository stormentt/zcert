package server

import (
	"encoding/json"
	"io/ioutil"

	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/stormentt/zcert/util"
)

func signCert(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})

		return
	}

	err = util.VerifyResp(body)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid authorization",
		})

		return
	}

	var j util.AuthResp
	json.Unmarshal(body, &j)

	switch csrb64 := j.Data["csr"].(type) {
	case string:
		_, err := util.DecodeB64(csrb64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err,
			})
			return
		}
	}
}
