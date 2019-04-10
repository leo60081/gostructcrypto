package gostructcrypto

type CryptoInterface interface {
	SetKey(key []byte)
	getKey() (key []byte)
	iskeyNil() bool
	setCryptoIndex(int)
	getCryptoIndex() int
	IsEncrypted() bool
	IsDecrypted() bool
	isEncryptoFuncNil() bool
	isDecryptoFuncNil() bool
	getEnCryptoFunc() func(key []byte, in []byte) (out []byte)
	getDeCryptoFunc() func(key []byte, in []byte) (out []byte, err error)
	SetEnCryptoFunc(func(key []byte, in []byte) (out []byte))
	SetDeCryptoFunc(func(key []byte, in []byte) (out []byte, err error))

	getEncodeFunc() func(in []byte) (out []byte)
	getDecodeFunc() func(in []byte) (out []byte, err error)
	SetEncodeFunc(func(in []byte) (out []byte))
	SetDecodeFunc(func(in []byte) (out []byte, err error))
	isEncodeFuncNil() bool
	isDecodeFuncNil() bool
}
