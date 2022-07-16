package server

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stormentt/zcert/middleware"
	"github.com/stormentt/zcert/util"
)

var CaCert *x509.Certificate
var CaKey ed25519.PrivateKey

func setup() error {
	certDir := viper.GetString("storage.path")
	caKeyPath := fmt.Sprintf("%s/%s", certDir, "ca.key")
	caCertPath := fmt.Sprintf("%s/%s", certDir, "ca.crt")

	var err error

	CaCert, err = util.DecodeX509Cert(caCertPath)
	if err != nil {
		return err
	}

	CaKey, err = util.DecodeEd25519Priv(caKeyPath)
	if err != nil {
		return err
	}

	return nil
}

func Serve() error {
	err := setup()
	if err != nil {
		return err
	}

	r := gin.Default()
	r.GET("/ca", getCA)

	authRoutes := r.Group("/", middleware.CheckAuth)
	authRoutes.POST("/sign", signCert)

	r.Run()

	return nil
}
