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

type NoPEMDataError struct {
	path string
}

func (e *NoPEMDataError) Error() string {
	return fmt.Sprintf("no PEM encoded data in %s", e.path)
}

func DecodeX509Cert(path string) (*x509.Certificate, error) {
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
		return nil, &NoPEMDataError{path: path}
	}

	return x509.ParseCertificate(block.Bytes)
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
