package funny

import (
    "log"
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "encoding/hex"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	opensslSaltHeader            = "Salted__"
	opensslAes256Pbkdf2Iteration = 10000
	opensslAes256KeyLength       = 32
	opensslAes256IvLength        = 16
)

func md5sum(text string) string {
    hash := md5.Sum([]byte(text))
    return hex.EncodeToString(hash[:])
}

func KeyGenerator(val string) string {
    return md5sum(val)[:32]
}

func NonceGenerator(val string) string {
    return KeyGenerator(val)[:12]
}

func Decrypt(ciphertext, key, nonce []byte) (plaintext []byte) {
    block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatal(err)
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Fatal(err)
    }

    plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        log.Fatal(err)
    }
    return
}

func Encrypt(plaintext, key, nonce []byte) []byte {
    block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatal(err)
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Fatal(err)
    }

    return aesgcm.Seal(nil, nonce, plaintext, nil)
}

func Validate(data1 []byte, data2 []byte) bool {
    return bytes.Equal(data1, data2)
}

func opensslAes256Decrypt(passphrase string, encryptedBase64 string) (string, error) {
	data := make([]byte, base64.StdEncoding.DecodedLen(len([]byte(encryptedBase64))))
	if n, err := base64.StdEncoding.Decode(data, []byte(encryptedBase64)); err != nil {
		return "", fmt.Errorf("Invalid string: %s", err)
	} else {
		data = data[:n]
	}

	if len(data) < aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return "", fmt.Errorf("Invalid data.")
	}

	salt := make([]byte, aes.BlockSize-8)
	if saltHeader := data[:aes.BlockSize]; string(saltHeader[:8]) != opensslSaltHeader {
		return "", fmt.Errorf("Invalid salt.")
	} else {
		salt = saltHeader[8:]
	}

	var m []byte
	prev := []byte{}
	for len(m) < opensslAes256KeyLength+opensslAes256IvLength {
		a := make([]byte, len(prev)+len(passphrase)+len(salt))
		copy(a, prev)
		copy(a[len(prev):], passphrase)
		copy(a[len(prev)+len(passphrase):], salt)

		h := sha256.New()
		h.Write(a)
		prev = h.Sum(nil)
		m = append(m, prev...)
	}

	key := m[:opensslAes256KeyLength]
	iv := m[opensslAes256KeyLength : opensslAes256KeyLength+opensslAes256IvLength]

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cbcDecrypter := cipher.NewCBCDecrypter(c, iv)
	cbcDecrypter.CryptBlocks(data[aes.BlockSize:], data[aes.BlockSize:])

	paddingLength := int(data[len(data)-1])
	if paddingLength > aes.BlockSize || paddingLength == 0 {
		return "", fmt.Errorf("Invalid padding.")
	}
	plaintext := data[aes.BlockSize : len(data)-paddingLength]

	return string(plaintext), nil
}

func OpensslAes256Pbkdf2Decrypt(passphrase string, encryptedBase64 string) (string, error) {
	data := make([]byte, base64.StdEncoding.DecodedLen(len([]byte(encryptedBase64))))
	if n, err := base64.StdEncoding.Decode(data, []byte(encryptedBase64)); err != nil {
		return "", fmt.Errorf("Invalid string: %s", err)
	} else {
		data = data[:n]
	}

	if len(data) < aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return "", fmt.Errorf("Invalid data.")
	}

	salt := make([]byte, aes.BlockSize-8)
	if saltHeader := data[:aes.BlockSize]; string(saltHeader[:8]) != opensslSaltHeader {
		return "", fmt.Errorf("Invalid salt.")
	} else {
		salt = saltHeader[8:]
	}

	m := pbkdf2.Key([]byte(passphrase), salt, opensslAes256Pbkdf2Iteration, opensslAes256KeyLength+opensslAes256IvLength, sha256.New)
	key := m[:opensslAes256KeyLength]
	iv := m[opensslAes256KeyLength : opensslAes256KeyLength+opensslAes256IvLength]

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cbcDecrypter := cipher.NewCBCDecrypter(c, iv)
	cbcDecrypter.CryptBlocks(data[aes.BlockSize:], data[aes.BlockSize:])

	paddingLength := int(data[len(data)-1])
	if paddingLength > aes.BlockSize || paddingLength == 0 {
		return "", fmt.Errorf("Invalid padding.")
	}
	plaintext := data[aes.BlockSize : len(data)-paddingLength]

	return string(plaintext), nil
}