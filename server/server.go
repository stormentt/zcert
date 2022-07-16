package server

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
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

func ginLogger(c *gin.Context) {
	start := time.Now()
	path := c.Request.URL.Path
	c.Next()

	elapsed := time.Since(start)

	log.WithFields(log.Fields{
		"method":  c.Request.Method,
		"path":    path,
		"elapsed": elapsed,
		"status":  c.Writer.Status(),
	}).Info("")
}
func Serve() error {
	err := setup()
	if err != nil {
		return err
	}

	r := gin.New()
	r.Use(ginLogger)
	r.Use(gin.Recovery())
	r.SetTrustedProxies(nil)

	gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
		log.WithFields(log.Fields{
			"method":  httpMethod,
			"handler": handlerName,
		}).Debug(absolutePath)
	}

	r.GET("/ca", getCA)
	authRoutes := r.Group("/", middleware.CheckAuth)
	authRoutes.POST("/sign", signCert)

	r.Run()

	return nil
}
