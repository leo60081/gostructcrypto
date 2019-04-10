package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type cbc struct {
	iv  []byte
	key []byte
}

func NewAseCBC(iv []byte) (c cbc) {
	l := len(iv)
	if l < aes.BlockSize {
		o := make([]byte, aes.BlockSize-l)
		iv = append(iv, o...)
		logger.Println("[WARN] IV (length=", l, ") must equal block size", aes.BlockSize, "auto reset IV to", iv)
	}
	if len(iv) > aes.BlockSize {
		iv = iv[:aes.BlockSize]
		logger.Println("[WARN] IV (length=", l, ") must equal block size", aes.BlockSize, "auto reset IV to", iv)
	}
	return cbc{
		iv: iv,
	}
}

func (c *cbc) Encrypt(key []byte, in []byte) (out []byte) {
	if c.key != nil {
		c.key = checkKey(c.key)
		key = c.key
	} else {
		key = checkKey(key)
		c.key = key
	}
	if c.iv == nil {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	paddedPlaintext := c.PKCS7Padding([]byte(in))
	cipherText := make([]byte, aes.BlockSize+len(paddedPlaintext))

	mode := cipher.NewCBCEncrypter(block, c.iv)
	mode.CryptBlocks(cipherText, paddedPlaintext)

	return cipherText[:len(cipherText)-aes.BlockSize]
}

func (c *cbc) Decrypt(key []byte, in []byte) (out []byte, err error) {
	if c.key != nil {
		c.key = checkKey(c.key)
		key = c.key
	} else {
		key = checkKey(key)
		c.key = key
	}
	if c.iv == nil {
		return nil, fmt.Errorf("missing iv")
	}
	defer func() {
		if i := recover(); i != nil {
			err = fmt.Errorf("err:%v", i)
		}
	}()
	decrypted := make([]byte, len(in))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, c.iv)
	mode.CryptBlocks(decrypted, in)

	return decrypted[:len(decrypted)-int(decrypted[len(decrypted)-1])], err
}

func (c *cbc) PKCS7Padding(data []byte) []byte {
	padSize := aes.BlockSize
	if len(data)%aes.BlockSize != 0 {
		padSize = aes.BlockSize - (len(data))%aes.BlockSize
	}

	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(data, pad...)
}

func checkKey(key []byte) (okkey []byte) {
	k := len(key)
	switch k {
	default:
		if k > 32 {
			okkey = key[:32]
			break
		}
		if k < 32 && k > 24 {
			o := make([]byte, 32-k)
			okkey = append(key, o...)
			break
		}
		if k < 24 && k > 16 {
			o := make([]byte, 24-k)
			okkey = append(key, o...)
			break
		}
		if k < 16 {
			o := make([]byte, 16-k)
			okkey = append(key, o...)
		}
	case 16, 24, 32:
		return key
	}
	logger.Println("[WARN] key (length=", k, ") should be the AES key, either 16, 24, or 32 bytes to select. auto reset key to", okkey)
	return okkey
}
