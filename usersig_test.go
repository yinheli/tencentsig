package tencentsig

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"log"
	"os"
	"strings"
	"testing"
)

var (
	sdkAppId   = "1234567890"
	identifier = "zhangshan"

	l = log.New(os.Stdout, "[tencentsig - test] ", log.LstdFlags)
)

func doVerifyUserSig(t *testing.T, pemPrivateKey, pemPublicKey string) {
	conf := NewConf(sdkAppId, identifier).WithExpire(defaultExpire)
	userSig, err := conf.GenUserSig(pemPrivateKey)
	assert.Nil(t, err)

	l.Print("userSig:", userSig)

	c, valid, err := VerifyUserSig(pemPublicKey, userSig)

	assert.Nil(t, err)
	assert.True(t, valid)

	b, _ := json.MarshalIndent(c, "", "  ")
	l.Print("conf:", string(b))
}

// 准备

/*

# list curves
openssl ecparam -list_curves


# prime256v1 curve

openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl pkcs8 -topk8 -nocrypt -in private.pem -out private-pkcs8.pem && cat private-pkcs8.pem
openssl ec -in private.pem -pubout


# secp256k1 curve

openssl ecparam -name secp256k1 -genkey -noout -out private.pem
openssl pkcs8 -topk8 -nocrypt -in private.pem -out private-pkcs8.pem && cat private-pkcs8.pem
openssl ec -in private.pem -pubout
*/

func TestVerifyUserSig(t *testing.T) {
	// prime256v1
	doVerifyUserSig(
		t,

		strings.TrimSpace(`
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJzqd3dF+O6vd+bGJ
7tGA7TLsWNzbYBKRGELEA65ywQahRANCAATIBFu6F5SlqrPFkuhi46IRXXKyEiuU
g8pP+n3L5ZSiW3o0N58P0Ix77PrRVSXLfHd5VqeyF2CWWDUQZyA/butY
-----END PRIVATE KEY-----
		`),

		strings.TrimSpace(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyARbuheUpaqzxZLoYuOiEV1yshIr
lIPKT/p9y+WUolt6NDefD9CMe+z60VUly3x3eVanshdgllg1EGcgP27rWA==
-----END PUBLIC KEY-----
		`),
	)

	// secp256k1
	doVerifyUserSig(
		t,

		strings.TrimSpace(`
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgkRrBHsxAXy4ssvSYsJIM
TUzzLIHOeUQ/QKygM3JhvDahRANCAATyucyxciWHFclVxRPW7zJ6d51F5au6xnZk
bjkiDOpa6gl8JhdeWcKLYgRb5raHNq/JYUYJSrsH29whxdx0lpq7
-----END PRIVATE KEY-----
		`),

		strings.TrimSpace(`
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE8rnMsXIlhxXJVcUT1u8yenedReWrusZ2
ZG45IgzqWuoJfCYXXlnCi2IEW+a2hzavyWFGCUq7B9vcIcXcdJaauw==
-----END PUBLIC KEY-----
		`),
	)
}
