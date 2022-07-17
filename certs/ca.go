package certs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stormentt/zcert/util"
)

var CA *x509.Certificate
var CAPrivKey ed25519.PrivateKey

type FileExistsError struct {
	path string
}

func (e *FileExistsError) Error() string {
	return fmt.Sprintf("file %s already exists! will not procede without -f", e.path)
}

func checkFile(f string, force bool) error {
	if _, err := os.Stat(f); err == nil {
		if !force {
			return &FileExistsError{path: f}
		} else {
			err = os.Remove(f)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getPkix() pkix.Name {
	/*
		should support:
			Country, Organization, OrganizationalUnit []string
			Locality, Province                        []string
			StreetAddress, PostalCode                 []string
			SerialNumber, CommonName                  string
	*/

	return pkix.Name{
		CommonName: viper.GetString("ca.name"),
	}
}

func CreateCA() error {
	certDir := viper.GetString("storage.path")
	force := viper.GetBool("force")

	if _, err := os.Stat(certDir); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(certDir, 0700)
		if err != nil {
			return err
		}
	}

	caKeyPath := fmt.Sprintf("%s/%s", certDir, "ca.key")
	caCertPath := fmt.Sprintf("%s/%s", certDir, "ca.crt")

	log.WithFields(log.Fields{
		"storage.path": certDir,
		"force":        force,
	}).Debug("creating a certificate authority")

	checkFiles := []string{caKeyPath, caCertPath}
	for _, f := range checkFiles {
		err := checkFile(f, force)
		if err != nil {
			return err
		}
	}

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               getPkix(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(viper.GetDuration("lifetime")),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	pubkey, privkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubkey, privkey)
	if err != nil {
		return err
	}

	crtBuf := new(bytes.Buffer)
	keyBuf := new(bytes.Buffer)

	// Encode Keys
	if err = util.EncodeX509Cert(crtBuf, caBytes); err != nil {
		return err
	}

	if err = util.EncodeEd25519Priv(keyBuf, privkey); err != nil {
		return err
	}

	// Create Files
	keyout, err := os.OpenFile(caKeyPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	certout, err := os.OpenFile(caCertPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	// Write Files
	if _, err = io.Copy(keyout, keyBuf); err != nil {
		return err
	}

	if _, err = io.Copy(certout, crtBuf); err != nil {
		return err
	}

	// Close Files
	if err = keyout.Close(); err != nil {
		return err
	}

	if err = certout.Close(); err != nil {
		return err
	}

	return nil
}

func LoadCA() error {
	certDir := viper.GetString("storage.path")
	caCrtPath := fmt.Sprintf("%s/%s", certDir, "ca.crt")
	caKeyPath := fmt.Sprintf("%s/%s", certDir, "ca.key")

	var err error

	CA, err = util.DecodeX509CertFromPath(caCrtPath)
	if err != nil {
		return err
	}

	CAPrivKey, err = util.DecodeEd25519Priv(caKeyPath)
	if err != nil {
		return err
	}

	return nil
}
