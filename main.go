package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
)

type credentialsConfig struct {
	PemPrivateKeyString string `json:"private_key"`
	ClientId            string `json:"client_id"`
}

func readCredentials() (*credentialsConfig, error) {
	jsonFile, err := os.Open("credentials.json")
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	value, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var cred credentialsConfig
	err = json.Unmarshal(value, &cred)
	if err != nil {
		return nil, err
	}

	return &cred, nil
}

func genToken(cred *credentialsConfig) (string, error) {
	now := time.Now()
	claim := jwt.MapClaims{
		"iss": os.Getenv("SERVICE_ACCOUNT_EMAIL"),
		// enter your scope here
		"scope": "https://www.googleapis.com/auth/drive",
		"aud":   "https://oauth2.googleapis.com/token",
		// token expiration maximum: 1 hour, see https://developers.google.com/identity/protocols/oauth2/service-account
		"exp": now.Add(time.Hour * 1).Unix(),
		"iat": now.Unix(),
	}

	pemBlok, _ := pem.Decode([]byte(cred.PemPrivateKeyString))
	if pemBlok == nil {
		log.Fatal("something went wrong, pem block nil")
	}

	privateKey, _ := x509.ParsePKCS8PrivateKey(pemBlok.Bytes)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)
	signedToken, err := token.SignedString(privateKey.(*rsa.PrivateKey))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

const (
	tokenUrl = "https://oauth2.googleapis.com/token"
)

func getAccessToken(token string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", url.QueryEscape(token))
	dataEncoded := data.Encode()
	res, err := http.Post(tokenUrl, "application/x-www-form-urlencoded", strings.NewReader(dataEncoded))
	if err != nil {
		return "", err
	}

	byteResp, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(byteResp), nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Failed to read env vars, err : %v\n", err)
	}

	cred, err := readCredentials()
	if err != nil {
		log.Fatalf("something went wrong %v", err)
	}

	signedToken, err := genToken(cred)
	if err != nil {
		log.Fatalf("something went wrong %v", err)
	}

	resp, err := getAccessToken(signedToken)
	if err != nil {
		log.Fatalf("something went wrong %v", err)
	}
	// You can retrieve access token from resp variable
	fmt.Println(resp)
}
