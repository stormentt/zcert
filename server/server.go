package server

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/spf13/viper"
	"github.com/stormentt/zcert/util"
)

var CaCert *x509.Certificate
var CaKey ed25519.PrivateKey

func Serve() error {
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
