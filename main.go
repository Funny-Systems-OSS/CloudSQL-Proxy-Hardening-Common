package funny

import (
    "crypto/aes"
	"crypto/cipher"
    "crypto/md5"
    "encoding/hex"
	"strconv"
)

const Banner = `
    ________ ___  ___  ________   ________       ___    ___
    |\  _____\\  \|\  \|\   ___  \|\   ___  \    |\  \  /  /|
    \ \  \__/\ \  \\\  \ \  \\ \  \ \  \\ \  \   \ \  \/  / /
     \ \   __\\ \  \\\  \ \  \\ \  \ \  \\ \  \   \ \    / /
      \ \  \_| \ \  \\\  \ \  \\ \  \ \  \\ \  \   \/  /  /
       \ \__\   \ \_______\ \__\\ \__\ \__\\ \__\__/  / /
        \|__|    \|_______|\|__| \|__|\|__| \|__|\___/ /
                                                \|___|/
`

func md5sum(text string) string {
    hash := md5.Sum([]byte(text))
    return hex.EncodeToString(hash[:])
}

func KeyGenerator(val int) string {
    return md5sum(strconv.Itoa(val))[:32]
}

func NonceGenerator(val int) string {
    return keyGenerator(val)[:12]
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