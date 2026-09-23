package auth

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/MoeclubM/metafusion-storage/internal/config"
)

func TestConfiguredPublicKeyRejectsPrivateMaterial(t *testing.T) {
	key := jwksTestKey(t)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("生成 PKCS#8 测试材料: %v", err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})
	for _, tc := range []struct{ name, value string }{
		{"pkcs1", string(pkcs1)},
		{"pkcs8", string(pkcs8)},
		{"base64_pkcs1", base64.StdEncoding.EncodeToString(pkcs1)},
		{"base64_pkcs8", base64.StdEncoding.EncodeToString(pkcs8)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(config.Config{JWTPublicKeyPEM: tc.value})
			if err == nil || !strings.Contains(err.Error(), "must be an RSA public key") {
				t.Fatalf("私钥材料必须被拒绝，错误类型: %T", err)
			}
		})
	}
}

func TestConfiguredPublicKeyAcceptsPublicFormats(t *testing.T) {
	key := jwksTestKey(t)
	pkixDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("生成 PKIX 测试公钥: %v", err)
	}
	pkix := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	for _, tc := range []struct{ name, value string }{
		{"pkix", string(pkix)},
		{"pkcs1", string(pkcs1)},
		{"base64_pkix", base64.StdEncoding.EncodeToString(pkix)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := New(config.Config{JWTPublicKeyPEM: tc.value})
			if err != nil {
				t.Fatalf("有效公钥被拒绝: %v", err)
			}
			if v.static == nil || v.static.N.Cmp(key.PublicKey.N) != 0 || v.static.E != key.PublicKey.E {
				t.Fatal("加载的公钥与输入不一致")
			}
		})
	}
}
