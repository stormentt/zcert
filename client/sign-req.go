package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/viper"
	"github.com/stormentt/zcert/apitypes"
	"github.com/stormentt/zcert/auth"
	"github.com/stormentt/zcert/certs"
	"github.com/stormentt/zcert/util"

	log "github.com/sirupsen/logrus"
)

func SignCSR(w io.Writer, r io.Reader) error {
	csr, err := util.DecodeX509CSR(r)
	if err != nil {
		return err
	}

	csrB64 := util.EncodeB64(csr.Raw)
	scr := apitypes.SignCertReq{
		CSR: csrB64,
		Params: certs.CSRParams{
			Lifetime:   time.Hour * 24 * 365,
			ClientAuth: true,
			ServerAuth: false,
		},
	}

	signed, err := sendCSR(scr)
	if err != nil {
		return err
	}

	_, err = w.Write(signed)
	return err
}

func sendCSR(scr apitypes.SignCertReq) ([]byte, error) {
	serverHost := viper.GetString("server")
	url := fmt.Sprintf("%s/sign", serverHost)

	jsonbody := new(bytes.Buffer)
	encoder := json.NewEncoder(jsonbody)
	if err := encoder.Encode(scr); err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", url, jsonbody)
	if err != nil {
		return nil, err
	}

	calcHMAC, err := auth.CalcHMAC(jsonbody.Bytes())
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-HMAC", util.EncodeB64(calcHMAC))

	log.WithFields(log.Fields{
		"hmac": util.EncodeB64(calcHMAC),
		"url":  url,
	}).Trace("sending request to server")

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"status": resp.StatusCode,
	}).Trace("received response from server")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{
			"status": resp.StatusCode,
			"body":   string(body),
		}).Error("received non 200 from server")

		return nil, nil
	}

	respExpHMACB64 := resp.Header.Get("Content-HMAC")
	respExpHMAC, err := util.DecodeB64(respExpHMACB64)
	if err != nil {
		return nil, err
	}

	match, err := auth.CheckHMAC(respExpHMAC, body)
	if err != nil {
		return nil, err
	}

	if !match {
		return nil, &auth.HMACMismatchError{}
	}

	return body, nil
}
