package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
)

type Issuer struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	caData []byte
}

func NewIssuer(caCertPath, caKeyPath string) (*Issuer, error) {
	caData, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, err
	}

	issuer := &Issuer{
		caCert: caCert,
		caKey:  caKey,
		caData: caData,
	}

	return issuer, nil
}

func (i *Issuer) CAData() []byte {
	return i.caData
}

func loadCA(caCertPath, caKeyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	//解析根证书
	caFile, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read ca cert file failed")
	}

	caBlock, _ := pem.Decode(caFile)

	cert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse ca cert failed")
	}
	//解析私钥
	keyFile, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read ca key file failed")
	}
	keyBlock, _ := pem.Decode(keyFile)
	praKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse private key failed")
	}

	return cert, praKey, nil
}

func (i *Issuer) Issue(commonName, host string) ([]byte, []byte, error) {
	cer := &x509.Certificate{
		SerialNumber: big.NewInt(1), // FIXME
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),                                                                 //证书有效期开始时间
		NotAfter:              time.Now().AddDate(100, 0, 0),                                              //证书有效期结束时间
		BasicConstraintsValid: true,                                                                       //基本的有效性约束
		IsCA:                  host != "",                                                                 //是否是根证书
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //证书用途(客户端认证，数据加密)
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
	}

	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			cer.IPAddresses = append(cer.IPAddresses, ip)
		} else {
			cer.DNSNames = append(cer.DNSNames, host)
		}
	}

	//生成公钥私钥对
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate private key failed")
	}

	der, err := x509.CreateCertificate(rand.Reader, cer, i.caCert, &key.PublicKey, i.caKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create cert failed")
	}

	//编码证书文件和私钥文件
	caPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	certByteBuffer := bytes.Buffer{}
	if err := pem.Encode(&certByteBuffer, caPem); err != nil {
		return nil, nil, errors.Wrap(err, "pem encode cert failed")
	}

	keyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	keyByteBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyByteBuffer, keyPem); err != nil {
		return nil, nil, errors.Wrap(err, "pem encode key failed")
	}

	return certByteBuffer.Bytes(), keyByteBuffer.Bytes(), nil
}

func (i *Issuer) IssueFiles(commonName, host, certFile, keyFile string) error {
	certData, keyData, err := i.Issue(commonName, host)
	if err != nil {
		return errors.Wrapf(err, "issue cert file for %s (%s) failed", commonName, host)
	}

	if err := ioutil.WriteFile(certFile, certData, 0600); err != nil {
		return errors.Wrapf(err, "save cert file %s failed", certFile)
	}

	if err := ioutil.WriteFile(keyFile, keyData, 0600); err != nil {
		return errors.Wrapf(err, "save key file %s failed", keyFile)
	}

	return nil
}

func (i *Issuer) NewTLSConfig(commonName, host string) (*tls.Config, error) {
	certData, keyData, err := i.Issue(commonName, host)
	if err != nil {
		return nil, errors.Wrap(err, "create srp server certs failed")
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(i.CAData())

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func main() {
	i, _ := NewIssuer("./cacert.pem", "./cakey.pem")
	i.IssueFiles("webhook-svc.default.svc", "webhook-svc.default.svc", "webhook.crt", "webhook.key")
}
