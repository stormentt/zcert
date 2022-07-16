package util

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"golang.org/x/crypto/blake2b"
)

type InvalidMACError struct{}

func (e *InvalidMACError) Error() string {
	return "expected MAC and computed MAC did not match"
}

type AuthResp struct {
	Data map[string]interface{} `json:"data"`
	Hash string                 `json:"hash"`
}

func AuthorizedResp(c *gin.Context, h gin.H) {
	j, err := json.Marshal(h)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})
		return
	}

	authkey := viper.GetString("authkey")
	b2, _ := blake2b.New256([]byte(authkey))
	b2.Write(j)
	hash := b2.Sum(nil)

	c.JSON(http.StatusOK, gin.H{
		"data": h,
		"hash": hash,
	})
}

func VerifyResp(b []byte) error {
	var resp AuthResp
	err := json.Unmarshal(b, &resp)
	if err != nil {
		return err
	}

	sentHash, err := DecodeB64(resp.Hash)
	if err != nil {
		return err
	}

	j, err := json.Marshal(resp.Data)
	if err != nil {
		return err
	}

	authkey := viper.GetString("authkey")
	b2, _ := blake2b.New256([]byte(authkey))
	b2.Write(j)
	calcHash := b2.Sum(nil)

	if subtle.ConstantTimeCompare(calcHash, sentHash) != 1 {
		return &InvalidMACError{}
	}

	return nil
}
