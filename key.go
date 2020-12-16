package funny

import (
    "log"
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "encoding/hex"
)

func Md5sum(text string) string {
    hash := md5.Sum([]byte(text))
    return hex.EncodeToString(hash[:])
}

func KeyGenerator(val string) string {
    return Md5sum(val)[:32]
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
