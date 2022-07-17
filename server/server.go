package server

import (
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zcert/certs"
	"github.com/stormentt/zcert/middleware"
	"github.com/stormentt/zcert/server/nonces"
)

var noncemanager nonces.NonceManager

func setup() error {
	return certs.LoadCA()
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
