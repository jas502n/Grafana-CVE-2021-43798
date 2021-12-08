package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

const (
	saltLength                   = 8
	aesCfb                       = "aes-cfb"
	aesGcm                       = "aes-gcm"
	encryptionAlgorithmDelimiter = '*'
)

func deriveEncryptionAlgorithm(payload []byte) (string, []byte, error) {
	if len(payload) == 0 {
		return "", nil, fmt.Errorf("unable to derive encryption algorithm")
	}

	if payload[0] != encryptionAlgorithmDelimiter {
		return aesCfb, payload, nil // backwards compatibility
	}

	payload = payload[1:]
	algDelim := bytes.Index(payload, []byte{encryptionAlgorithmDelimiter})
	if algDelim == -1 {
		return aesCfb, payload, nil // backwards compatibility
	}

	algB64 := payload[:algDelim]
	payload = payload[algDelim+1:]

	alg := make([]byte, base64.RawStdEncoding.DecodedLen(len(algB64)))

	_, err := base64.RawStdEncoding.Decode(alg, algB64)
	if err != nil {
		return "", nil, err
	}

	return string(alg), payload, nil
}

func decryptGCM(block cipher.Block, payload []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := payload[saltLength : saltLength+gcm.NonceSize()]
	ciphertext := payload[saltLength+gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Key needs to be 32bytes
func encryptionKeyToBytes(secret, salt string) ([]byte, error) {
	return pbkdf2.Key([]byte(secret), []byte(salt), 10000, 32, sha256.New), nil
}

func decryptCFB(block cipher.Block, payload []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(payload) < aes.BlockSize {
		return nil, errors.New("payload too short")
	}

	iv := payload[saltLength : saltLength+aes.BlockSize]
	payload = payload[saltLength+aes.BlockSize:]
	payloadDst := make([]byte, len(payload))

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(payloadDst, payload)
	return payloadDst, nil
}

func Decrypt(payload []byte, secret string) ([]byte, error) {
	alg, payload, err := deriveEncryptionAlgorithm(payload)
	if err != nil {
		return nil, err
	}

	if len(payload) < saltLength {
		return nil, fmt.Errorf("unable to compute salt")
	}
	salt := payload[:saltLength]
	key, err := encryptionKeyToBytes(secret, string(salt))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch alg {
	case aesGcm:
		return decryptGCM(block, payload)
	default:
		return decryptCFB(block, payload)
	}
}

// Encrypt encrypts a payload with a given secret.
// DEPRECATED. Do not use it.
// Use secrets.Service instead.
func Encrypt(payload []byte, secret string) ([]byte, error) {
	salt, err := GetRandomString(saltLength)
	if err != nil {
		return nil, err
	}

	key, err := encryptionKeyToBytes(secret, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, saltLength+aes.BlockSize+len(payload))
	copy(ciphertext[:saltLength], salt)
	iv := ciphertext[saltLength : saltLength+aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[saltLength+aes.BlockSize:], payload)

	return ciphertext, nil
}

// GetRandomString generate random string by specify chars.
// source: https://github.com/gogits/gogs/blob/9ee80e3e5426821f03a4e99fad34418f5c736413/modules/base/tool.go#L58
func GetRandomString(n int, alphabets ...byte) (string, error) {
	const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i, b := range bytes {
		if len(alphabets) == 0 {
			bytes[i] = alphanum[b%byte(len(alphanum))]
		} else {
			bytes[i] = alphabets[b%byte(len(alphabets))]
		}
	}
	return string(bytes), nil
}

func main() {
	// decode base64str
	var grafanaIni_secretKey = "SW2YcwTIb9zpOOhoPsMm"
	var dataSourcePassword = "R3pMVVh1UHLoUkTJOl+Z/sFymLqolUOVtxCtQL/y+Q=="
	encrypted, _ := base64.StdEncoding.DecodeString(dataSourcePassword)
	PwdBytes, _ := Decrypt(encrypted, grafanaIni_secretKey)
	fmt.Println("[*] grafanaIni_secretKey= " + grafanaIni_secretKey)
	fmt.Println("[*] DataSourcePassword= " + dataSourcePassword)
	fmt.Println("[*] plainText= " + string(PwdBytes))

	fmt.Println("\n")
	// encode str (dataSourcePassword)
	var PlainText = "jas502n"
	encryptedByte, _ := Encrypt([]byte(PlainText), grafanaIni_secretKey)
	var encryptedStr = base64.StdEncoding.EncodeToString(encryptedByte)
	fmt.Println("[*] grafanaIni_secretKey= " + grafanaIni_secretKey)
	fmt.Println("[*] PlainText= " + PlainText)
	fmt.Println("[*] EncodePassword= " + encryptedStr)
}
