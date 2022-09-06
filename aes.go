package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/forgoer/openssl"
)

// Encryption
func Encrypt(value, key string) (string, error) {
	iv := make([]byte, 16)

	_, err := rand.Read(iv)
	if err != nil {
		return "", err
	}

	// PHP Serialization
	/* 	message, err := serialize.Marshal(value)
	   	if err != nil {
	   		return "", err
	   	} */

	//Encryption value
	res, err := openssl.AesCBCEncrypt( /* message */ []byte(value), []byte(key), iv, openssl.PKCS7_PADDING)
	if err != nil {
		return "", errors.New("AesCBCEncrypt failed" + err.Error())
	}

	//Base64 encryption
	resVal := base64.StdEncoding.EncodeToString(res)
	resIv := base64.StdEncoding.EncodeToString(iv)

	//Generate MAC value
	data := resIv + resVal
	mac := computeHmacSha256(data, key)

	//Construct ticket structure
	ticket := make(map[string]interface{})
	ticket["iv"] = resIv
	ticket["mac"] = mac
	ticket["value"] = resVal

	//JSON serialization
	resTicket, err := json.Marshal(ticket)
	if err != nil {
		return "", errors.New("Marshal failed" + err.Error())
	}

	//Base64 encryptionticket
	ticketR := base64.StdEncoding.EncodeToString(resTicket)

	return ticketR, nil
}

// Decryption
func Decrypt(value, key string) (string, error) {

	//Base64 decryption
	token, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", errors.New("token failed" + err.Error())
	}

	//JSON deserialization
	tokenJson := make(map[string]string)
	err = json.Unmarshal(token, &tokenJson)
	if err != nil {
		return "", errors.New("tokenJson failed" + err.Error())
	}

	log.Printf("token: %s\n", token)
	log.Printf("tokenJson: %s\n", tokenJson)

	tokenJsonIv, okIv := tokenJson["iv"]
	tokenJsonValue, okValue := tokenJson["value"]
	tokenJsonMac, okMac := tokenJson["mac"]
	if !okIv || !okValue || !okMac {
		return "", errors.New("value is not full")
	}

	//Mac check to prevent data tampering
	data := tokenJsonIv + tokenJsonValue
	check := checkMAC(data, tokenJsonMac, key)
	if !check {
		return "", errors.New("mac valid failed")
	}

	//Base64 decryption iv & value
	tokenIv, err := base64.StdEncoding.DecodeString(tokenJsonIv)
	if err != nil {
		return "", errors.New("DecodeString failed" + err.Error())
	}

	tokenValue, err := base64.StdEncoding.DecodeString(tokenJsonValue)
	if err != nil {
		return "", errors.New("DecodeString failed" + err.Error())
	}

	//AES decryption value
	dst, err := openssl.AesCBCDecrypt(tokenValue, []byte(key), tokenIv, openssl.PKCS7_PADDING)
	if err != nil {
		return "", errors.New("AesCBCDecrypt failed" + err.Error())
	}

	// PHP Deserialization
	/* 	res, err := serialize.UnMarshal(dst)
	if err != nil {
		return "", err
	}
	return res.(string), nil */

	return string(dst), err
}

// Compare the expected hash with the actual hash
func checkMAC(message, msgMac, secret string) bool {
	expectedMAC := computeHmacSha256(message, secret)
	return hmac.Equal([]byte(expectedMAC), []byte(msgMac))
}

// Calculate MAC value
func computeHmacSha256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

// Processing key from OS environment
func GetKey() string {

	appKey := os.Getenv("AES_KEY")

	if strings.HasPrefix(appKey, "base64:") {
		split := appKey[7:]
		if key, err := base64.StdEncoding.DecodeString(split); err == nil {
			return string(key)
		}
		return split
	}
	return appKey
}
