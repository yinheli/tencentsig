package tencentsig

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"time"
)

const (
	accountType   = "0"
	appidAt3rd    = "0"
	version       = "201512300000"
	defaultExpire = 3600 * 24 * 180
)

var (
	tlsReplace = map[string]string{
		"+": "*",
		"/": "-",
		"=": "_",
	}
)

type Conf struct {
	AccountType string `json:"TLS.account_type"`
	Identifier  string `json:"TLS.identifier"`
	AppidAt3rd  string `json:"TLS.appid_at_3rd"`
	SdkAppid    string `json:"TLS.sdk_appid"`
	ExpireAfter string `json:"TLS.expire_after"`
	Version     string `json:"TLS.version"`
	Time        string `json:"TLS.time"`
	Sig         string `json:"TLS.sig"`
}

func NewConf(sdkAppId string, identifier string) *Conf {
	return &Conf{
		AccountType: accountType,
		Identifier:  identifier,
		AppidAt3rd:  appidAt3rd,
		SdkAppid:    sdkAppId,
		ExpireAfter: fmt.Sprintf("%d", defaultExpire),
		Version:     version,
		Time:        fmt.Sprintf("%d", time.Now().Unix()),
	}
}

func (c *Conf) WithExpire(expireInSeconds int) *Conf {
	c.ExpireAfter = fmt.Sprintf("%d", expireInSeconds)
	return c
}

func (c *Conf) GenUserSig(pemPrivateKey string) (string, error) {
	var err error
	c.Sig, err = c.sign(pemPrivateKey)
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(c)

	var b bytes.Buffer
	z := zlib.NewWriter(&b)
	z.Write(data)
	z.Close()

	return base64Encode(b.Bytes()), nil
}

func VerifyUserSig(pemPublicKey string, userSig string) (*Conf, bool, error) {
	data, err := base64Decode(userSig)
	if err != nil {
		return nil, false, err
	}
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false, err
	}

	data, err = ioutil.ReadAll(reader)
	if err != nil {
		return nil, false, err
	}

	var conf Conf
	err = json.Unmarshal(data, &conf)
	if err != nil {
		return nil, false, err
	}

	block, _ := pem.Decode([]byte(pemPublicKey))

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported elliptic curve") {
			var pki publicKeyInfo
			if _, err := asn1.Unmarshal(block.Bytes, &pki); err != nil {
				return nil, false, err
			}

			asn1Data := pki.PublicKey.RightAlign()
			fmt.Println(hex.EncodeToString(asn1Data))
			paramsData := pki.Algorithm.Parameters.FullBytes
			namedCurveOID := new(asn1.ObjectIdentifier)
			_, err = asn1.Unmarshal(paramsData, namedCurveOID)
			if err != nil {
				return nil, false, err
			}

			if namedCurveOID.Equal(oidNamedCurveS256) {
				pubk := new(ecdsa.PublicKey)
				pubk.Curve = S256()
				pubk.X, pubk.Y = elliptic.Unmarshal(pubk.Curve, asn1Data)
				pk = pubk
			}
		} else {
			return nil, false, err
		}
	}

	pubKey := pk.(*ecdsa.PublicKey)

	content := conf.signContent()
	hashed := sha256.Sum256([]byte(content))

	signature, _ := base64.StdEncoding.DecodeString(conf.Sig)
	r, s, err := pointsFromDER(signature)
	if err != nil {
		return nil, false, err
	}

	res := ecdsa.Verify(pubKey, hashed[:], r, s)
	return &conf, res, nil
}

func (c *Conf) signContent() string {
	var builder strings.Builder

	builder.WriteString("TLS.appid_at_3rd:")
	builder.WriteString(c.AppidAt3rd)
	builder.WriteString("\n")

	builder.WriteString("TLS.account_type:")
	builder.WriteString(c.AccountType)
	builder.WriteString("\n")

	builder.WriteString("TLS.identifier:")
	builder.WriteString(c.Identifier)
	builder.WriteString("\n")

	builder.WriteString("TLS.sdk_appid:")
	builder.WriteString(c.SdkAppid)
	builder.WriteString("\n")

	builder.WriteString("TLS.time:")
	builder.WriteString(c.Time)
	builder.WriteString("\n")

	builder.WriteString("TLS.expire_after:")
	builder.WriteString(c.ExpireAfter)
	builder.WriteString("\n")

	return builder.String()
}

func (c *Conf) sign(privateKey string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))

	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if strings.Contains(err.Error(), "unknown elliptic curve") {
			var privKey pkcs8
			if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
				return "", err
			}

			if privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA) {
				namedCurveOID := new(asn1.ObjectIdentifier)
				asn1.Unmarshal(privKey.Algo.Parameters.FullBytes, namedCurveOID)
				if namedCurveOID.Equal(oidNamedCurveS256) {
					var ecPrivKey ecPrivateKey
					asn1.Unmarshal(privKey.PrivateKey, &ecPrivKey)

					k := new(ecdsa.PrivateKey)
					k.Curve = S256()
					d := new(big.Int)
					d.SetBytes(ecPrivKey.PrivateKey)
					k.D = d
					k.X, k.Y = S256().ScalarBaseMult(d.Bytes())
					pk = k
				}
			}
		} else {
			return "", err
		}
	}

	priv := pk.(*ecdsa.PrivateKey)

	content := c.signContent()

	hashed := sha256.Sum256([]byte(content))

	sig, err := priv.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func base64Encode(data []byte) string {
	res := base64.StdEncoding.EncodeToString(data)
	for k, v := range tlsReplace {
		res = strings.Replace(res, k, v, -1)
	}
	return res
}

func base64Decode(data string) ([]byte, error) {
	for k, v := range tlsReplace {
		data = strings.Replace(data, v, k, -1)
	}
	return base64.StdEncoding.DecodeString(data)
}

func pointsFromDER(der []byte) (R, S *big.Int, err error) {
	R, S = &big.Int{}, &big.Int{}

	data := asn1.RawValue{}
	if _, err = asn1.Unmarshal(der, &data); err != nil {
		return
	}

	// The format of our DER string is 0x02 + rlen + r + 0x02 + slen + s
	rLen := data.Bytes[1] // The entire length of R + offset of 2 for 0x02 and rlen
	r := data.Bytes[2 : rLen+2]
	// Ignore the next 0x02 and slen bytes and just take the start of S to the end of the byte array
	s := data.Bytes[rLen+4:]

	R.SetBytes(r)
	S.SetBytes(s)

	return
}
