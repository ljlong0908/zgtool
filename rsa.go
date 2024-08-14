package zgtool

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// GenerateRSAKeyPair 生成RSA密钥对并返回公私钥字符串
func GenerateRSAKeyPair() (privateKeyStr, publicKeyStr string, err error) {
	// 生成 RSA 私钥对象
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}

	// 通过x509标准将得到的ras私钥序列化为 ASN.1 的 DER 编码字符串
	x509PrivateKey, _ := x509.MarshalPKCS8PrivateKey(privateKey)

	privateKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{},
		Bytes:   x509PrivateKey,
	})
	privateKeyStr = string(privateKeyBytes)

	// X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: map[string]string{},
		Bytes:   X509PublicKey,
	})
	publicKeyStr = string(publicKeyBytes)
	return
}

// Sign 私钥加签
func Sign(privateKeyStr, plainText string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil {
		return "", errors.New("Sign PrivateKey error")
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	h := sha1.New() //进行SHA1的散列
	h.Write([]byte(plainText))
	hashed := h.Sum(nil)

	// 进行rsa加密签名
	signedData, err := rsa.SignPKCS1v15(rand.Reader, private.(*rsa.PrivateKey), crypto.SHA1, hashed)
	if err != nil {
		return "", err
	}
	data := base64.StdEncoding.EncodeToString(signedData)

	return data, nil
}

// Verify 公钥验签
func Verify(publicKeyStr, originalData, signData string) error {
	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil {
		return errors.New("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	hash := sha1.New()
	hash.Write([]byte(originalData))
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA1, hash.Sum(nil), sign)
}
