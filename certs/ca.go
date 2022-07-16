package certs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

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

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	privbytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return err
	}

	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privbytes,
	})

	keyout, err := os.OpenFile(caKeyPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	certout, err := os.OpenFile(caCertPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	if _, err = io.Copy(keyout, caPrivKeyPEM); err != nil {
		return err
	}

	if _, err = io.Copy(certout, caPEM); err != nil {
		return err
	}

	if err = keyout.Close(); err != nil {
		return err
	}

	if err = certout.Close(); err != nil {
		return err
	}

	return nil
}
