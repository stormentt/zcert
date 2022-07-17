package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/stormentt/zcert/db"
	"github.com/stormentt/zcert/util"
)

type CSRParams struct {
	Lifetime   time.Duration
	ClientAuth bool
	ServerAuth bool
}

func ParseCSR(bytesB64 string) (*x509.CertificateRequest, error) {
	data, err := util.DecodeB64(bytesB64)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(data)
}

func ValidateCSR(csr *x509.CertificateRequest) error {
	return csr.CheckSignature()
}

func SignCSR(csr *x509.CertificateRequest, params CSRParams) ([]byte, error) {
	extKeyUsage := []x509.ExtKeyUsage{}
	if params.ClientAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	if params.ServerAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	serial := db.NextSerial()

	crt := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(params.Lifetime),
		IsCA:         false,
		ExtKeyUsage:  extKeyUsage,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, crt, CA, csr.PublicKey, CAPrivKey)
	if err != nil {
		return nil, err
	}

	crtBuf := new(bytes.Buffer)
	if err = util.EncodeX509Cert(crtBuf, crtBytes); err != nil {
		return nil, err
	}

	sigCert := db.SignedCertificate{
		ID:        serial,
		NotBefore: crt.NotBefore,
		NotAfter:  crt.NotAfter,

		Issuer:  CA.Subject,
		Subject: crt.Subject,
	}

	if err = db.DB.Create(&sigCert).Error; err != nil {
		return nil, err
	}

	return crtBuf.Bytes(), nil
}
