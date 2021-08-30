package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// https://github.com/golang/go/issues/33310#issuecomment-537251383
var maxSerialNumber = new(big.Int).SetBytes([]byte{127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})

func genCert(args []string) (err error) {
	privKeyBytes, err := os.ReadFile("ca.key")
	if err != nil {
		return err
	}
	b, _ := pem.Decode(privKeyBytes)
	privKey, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}
	caCertBytes, err := os.ReadFile("ca.pem")
	if err != nil {
		return err
	}
	b, _ = pem.Decode(caCertBytes)
	caCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return fmt.Errorf("parsing ca cert: %w", err)
	}
	//caCert, err := tls.LoadX509KeyPair("ca.pem", "ca.key")
	//if err != nil {
	//	return err
	//}
	serialNumber, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return
	}
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"btlink"},
			OrganizationalUnit: []string{"root CA"},
			CommonName:         args[0],
		},
		SerialNumber: serialNumber,
		DNSNames:     args[1:],
		// https://stackoverflow.com/a/65239775/149482
		NotAfter:  time.Now().AddDate(1, 0, 0),
		NotBefore: time.Now(),
	}, caCert, &privKey.PublicKey, privKey)
	if err != nil {
		return err
	}
	err = pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	return
}
