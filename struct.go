package gostructcrypto

import (
	"sync"

	"github.com/leo60081/gostructcrypto/aes"
	"github.com/leo60081/gostructcrypto/encode"
)

// usage: embedding to your struct, such like:
// type Foo struct {
//   	Password   string   `crypto:"required"`
//   	gostructcrypto.Crypto   `-`
// }
type Crypto struct {
	mux      sync.Mutex
	index    *int
	key      []byte
	enCrypto func(key []byte, in []byte) (out []byte)
	deCrypto func(key []byte, in []byte) (out []byte, err error)
	encode   func(in []byte) (out []byte)
	decode   func(in []byte) (out []byte, err error)
}

func (c *Crypto) SetKey(key []byte) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.key = key
	return
}

func (c *Crypto) iskeyNil() (t bool) {
	if c.key == nil {
		return true
	}
	return false
}

func (c *Crypto) getKey() (key []byte) {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.key == nil {
		c.key = GetGlobalKey()
	}
	return c.key
}

func (c *Crypto) getCryptoIndex() (v int) {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.index == nil {
		return -1
	}
	return *c.index
}

func (c *Crypto) setCryptoIndex(v int) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.index = &v
	return
}

func (c *Crypto) IsEncrypted() (r bool) {
	if c.getCryptoIndex() > 0 {
		return true
	} else {
		return false
	}
}

func (c *Crypto) IsDecrypted() (r bool) {
	if c.index == nil {
		return false
	}
	if c.getCryptoIndex() == 0 {
		return true
	} else {
		return false
	}
}

func (c *Crypto) isEncryptoFuncNil() (t bool) {
	if c.enCrypto != nil {
		return false
	}
	return true
}

func (c *Crypto) isDecryptoFuncNil() (t bool) {
	if c.deCrypto != nil {
		return false
	}
	return true
}

func (c *Crypto) getEnCryptoFunc() (enCrypto func(key []byte, in []byte) (out []byte)) {
	if c.enCrypto != nil {
		return c.enCrypto
	}
	return aes.AESEncrypt
}

func (c *Crypto) getDeCryptoFunc() (deCrypto func(key []byte, in []byte) (out []byte, err error)) {
	if c.deCrypto != nil {
		return c.deCrypto
	}
	return aes.AESDecrypt
}

func (c *Crypto) SetEnCryptoFunc(enCrypto func(key []byte, in []byte) (out []byte)) {
	c.enCrypto = enCrypto
	return
}

func (c *Crypto) SetDeCryptoFunc(deCrypto func(key []byte, in []byte) (out []byte, err error)) {
	c.deCrypto = deCrypto
	return
}

func (c *Crypto) getEncodeFunc() (encodeFunc func(in []byte) (out []byte)) {
	if c.encode != nil {
		return c.encode
	}
	return encode.Base64Encode
}

func (c *Crypto) getDecodeFunc() (decodeFunc func(in []byte) (out []byte, err error)) {
	if c.decode != nil {
		return c.decode
	}
	return encode.Base64Decode
}

func (c *Crypto) SetEncodeFunc(encodeFunc func(in []byte) (out []byte)) {
	c.encode = encodeFunc
}

func (c *Crypto) SetDecodeFunc(decodeFunc func(in []byte) (out []byte, err error)) {
	c.decode = decodeFunc
}

func (c *Crypto) isEncodeFuncNil() (t bool) {
	if c.encode != nil {
		return false
	}
	return true
}

func (c *Crypto) isDecodeFuncNil() (t bool) {
	if c.decode != nil {
		return false
	}
	return true
}
