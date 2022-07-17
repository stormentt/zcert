package util

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type NotEd25519KeyError struct {
	path string
}

func (e *NotEd25519KeyError) Error() string {
	return fmt.Sprintf("data in %s is not an ed25519 private key", e.path)
}

type NoPEMDataError struct{}

func (e *NoPEMDataError) Error() string {
	return fmt.Sprintf("no PEM encoded data in source")
}

func DecodeX509CertFromPath(path string) (*x509.Certificate, error) {
	inFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return DecodeX509Cert(inFile)
}
func DecodeX509Cert(r io.Reader) (*x509.Certificate, error) {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		return nil, &NoPEMDataError{}
	}

	return x509.ParseCertificate(block.Bytes)
}

func DecodeX509CSRFromPath(path string) (*x509.CertificateRequest, error) {
	inFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return DecodeX509CSR(inFile)
}

func DecodeX509CSR(r io.Reader) (*x509.CertificateRequest, error) {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		return nil, &NoPEMDataError{}
	}

	return x509.ParseCertificateRequest(block.Bytes)
}

func DecodeEd25519Priv(path string) (ed25519.PrivateKey, error) {
	inFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, inFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		return nil, err
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch v := key.(type) {
	case ed25519.PrivateKey:
		return v, nil
	default:
		return nil, &NotEd25519KeyError{path: path}
	}
}

func EncodeX509Cert(buf *bytes.Buffer, b []byte) error {
	return pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})
}

func EncodeEd25519Priv(buf *bytes.Buffer, key ed25519.PrivateKey) error {
	keybytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	return pem.Encode(buf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keybytes,
	})
}
