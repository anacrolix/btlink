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
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject: pkix.Name{
			CommonName: args[0],
		},
		SerialNumber: big.NewInt(0),
		DNSNames:     args[1:],
		NotAfter:     time.Now().AddDate(10, 0, 0),
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
