package funny

import (
    "log"
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "encoding/hex"
    "strconv"
)

const Funny = `
    ________ ___  ___  ________   ________       ___    ___
    |\  _____\\  \|\  \|\   ___  \|\   ___  \    |\  \  /  /|
    \ \  \__/\ \  \\\  \ \  \\ \  \ \  \\ \  \   \ \  \/  / /
     \ \   __\\ \  \\\  \ \  \\ \  \ \  \\ \  \   \ \    / /
      \ \  \_| \ \  \\\  \ \  \\ \  \ \  \\ \  \   \/  /  /
       \ \__\   \ \_______\ \__\\ \__\ \__\\ \__\__/  / /
        \|__|    \|_______|\|__| \|__|\|__| \|__|\___/ /
                                                \|___|/
`

func Md5sum(text string) string {
    hash := md5.Sum([]byte(text))
    return hex.EncodeToString(hash[:])
}

func KeyGenerator(val int) string {
    return Md5sum(strconv.Itoa(val))[:32]
}

func NonceGenerator(val int) string {
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