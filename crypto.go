package gostructcrypto

import (
	"reflect"
	"strings"
)

//
// runN: number of times to encrypt, default is 1
// enCryptedN: number of executions
//
func EnCryptoStruct(in CryptoInterface, runN ...int) (enCryptedN int, isEnCrypted bool) {
	defer func() {
		isEnCrypted = in.IsEncrypted()
	}()
	if isZero(reflect.ValueOf(in)) {
		logger.Println(reflect.TypeOf(in), " should be pointer")
		return
	}
	_n := 1
	if len(runN) > 0 {
		_n = runN[0]
	}
	if _n <= 0 {
		logger.Println("runN must be a greater than zero.")
		return
	}
	isDo := false
	_key := in.getKey()
	for enCryptedN = 0; enCryptedN < _n; enCryptedN++ {
		v := reflect.ValueOf(in).Elem()
		count := v.NumField()
		for i := 0; i < count; i++ {
			f := v.Field(i)
			n := v.Type().Field(i)

			if f.Type().Kind() == reflect.Ptr {
				c, ok := f.Interface().(CryptoInterface)
				if ok {
					if c.iskeyNil() {
						c.SetKey(in.getKey())
					}
					if c.isEncodeFuncNil() {
						c.SetEncodeFunc(in.getEncodeFunc())
						c.SetDecodeFunc(in.getDecodeFunc())
					}
					if c.isEncryptoFuncNil() {
						c.SetEnCryptoFunc(in.getEnCryptoFunc())
						c.SetDeCryptoFunc(in.getDeCryptoFunc())
					}
					t, _ := EnCryptoStruct(c)
					if t > 0 {
						isDo = true
					}
					continue
				}
			}
			needEncode := false
			if strings.Index(n.Tag.Get("encode"), "required") > -1 {
				needEncode = true
			}

			if strings.Index(n.Tag.Get("crypto"), "required") > -1 {
				if isZero(f) {
					continue
				}
				switch f.Type().Kind() {
				case reflect.Ptr:
					switch f.Type() {
					case reflect.TypeOf(new(string)):
						s, ok := f.Interface().(*string)
						if ok {
							if s != nil && *s != "" {
								o := in.getEnCryptoFunc()(_key, []byte(*s))
								if needEncode {
									o = in.getEncodeFunc()(o)
								}
								*s = string(o)
								f.Set(reflect.ValueOf(s))
								isDo = true
							}
						}
					case reflect.PtrTo(reflect.TypeOf([]byte{})):
						b, ok := f.Interface().(*[]byte)
						if ok {
							if b != nil && len(*b) == 0 {
								*b = in.getEnCryptoFunc()(_key, *b)
								if needEncode {
									*b = in.getEncodeFunc()(*b)
								}
								f.Set(reflect.ValueOf(b))
								isDo = true
							}
						}

					default:
						continue
					}

				case reflect.Slice:
					_, ok := f.Interface().([]byte)
					if ok {
						if len(f.Bytes()) == 0 {
							continue
						}
						o := in.getEnCryptoFunc()(_key, f.Bytes())
						if needEncode {
							o = in.getEncodeFunc()(o)
						}
						f.SetBytes(o)
						isDo = true
						continue
					}
					s, ok := f.Interface().([]string)
					if ok {
						if len(s) == 0 {
							continue
						}
						var e []string
						var o []byte
						for _, _s := range s {
							if _s == "" {
								continue
							}
							o = in.getEnCryptoFunc()(_key, []byte(_s))
							if needEncode {
								o = in.getEncodeFunc()(o)
							}
							e = append(e, string(o))
							isDo = true
						}
						f.Set(reflect.ValueOf(e))
						continue
					}
				case reflect.String:
					if f.String() == "" {
						continue
					}
					o := in.getEnCryptoFunc()(_key, []byte(f.String()))
					if needEncode {
						o = in.getEncodeFunc()(o)
					}
					f.SetString(string(o))
					isDo = true
				}
			}
		}
		if isDo == false {
			return
		}
		if in.getCryptoIndex() == -1 {
			in.setCryptoIndex(1)
		} else {
			in.setCryptoIndex(in.getCryptoIndex() + 1)
		}
	}
	return
}

//
// runN: number of times to decrypt, default is 1
// deCryptedN: number of executions
//
func DecryptoStruct(in CryptoInterface, runN ...int) (deCryptedN int, isDeCrypted bool) {
	defer func() {
		isDeCrypted = in.IsDecrypted()
	}()
	if isZero(reflect.ValueOf(in)) {
		logger.Println(reflect.TypeOf(in), " should be pointer")
		return
	}
	_n := 1
	if len(runN) > 0 {
		_n = runN[0]
	}
	if _n <= 0 {
		logger.Println("runN must be a greater than zero.")
		return
	}
	if _n == 1 && in.IsDecrypted() {
		return
	}
	isDo := false
	_key := in.getKey()
	for deCryptedN = 0; deCryptedN < _n; deCryptedN++ {
		v := reflect.ValueOf(in).Elem()
		c_in := v.Interface()
		count := v.NumField()
		for i := 0; i < count; i++ {
			f := v.Field(i)
			n := v.Type().Field(i)
			if f.Type().Kind() == reflect.Ptr {
				c, ok := f.Interface().(CryptoInterface)

				if ok {
					if c.iskeyNil() {
						c.SetKey(in.getKey())
					}
					if c.isDecodeFuncNil() {
						c.SetEncodeFunc(in.getEncodeFunc())
						c.SetDecodeFunc(in.getDecodeFunc())
					}
					if c.isDecryptoFuncNil() {
						c.SetEnCryptoFunc(in.getEnCryptoFunc())
						c.SetDeCryptoFunc(in.getDeCryptoFunc())
					}
					t, _ := DecryptoStruct(c)
					if t > 0 {
						isDo = true
					}
					continue
				}
			}
			needDecode := false
			if strings.Index(n.Tag.Get("encode"), "required") > -1 {
				needDecode = true
			}

			if strings.Index(n.Tag.Get("crypto"), "required") > -1 {
				if isZero(f) {
					continue
				}
				switch f.Type().Kind() {
				case reflect.Ptr:
					switch f.Type() {
					case reflect.TypeOf(new(string)):
						s, ok := f.Interface().(*string)
						if ok {
							if s != nil && *s != "" {
								o := []byte(*s)
								var err error
								if needDecode {
									o, err = in.getDecodeFunc()(o)
									if err != nil {
										logger.Println("decode err:", err.Error())
										reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
										return
									}
								}
								o, err = in.getDeCryptoFunc()(_key, o)
								if err != nil {
									logger.Println("decryption err:", err.Error())
									reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
									return
								}

								ss := string(o)
								f.Set(reflect.ValueOf(&ss))
								isDo = true
							}
						}
					case reflect.PtrTo(reflect.TypeOf([]byte{})):
						b, ok := f.Interface().(*[]byte)
						if ok {
							if b != nil && len(*b) != 0 {
								o := *b
								var err error
								if needDecode {
									o, err = in.getDecodeFunc()(o)
									if err != nil {
										logger.Println("decode err:", err.Error())
										reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
										return
									}
								}
								o, err = in.getDeCryptoFunc()(_key, o)
								if err != nil {
									logger.Println("decryption err:", err.Error())
									reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
									return
								}
								f.Set(reflect.ValueOf(&o))
								isDo = true
							}
							continue
						}
					default:
						continue
					}

				case reflect.Slice:
					_, ok := f.Interface().([]byte)
					if ok {
						if len(f.Bytes()) == 0 {
							continue
						}
						o := f.Bytes()
						var err error
						if needDecode {
							o, err = in.getDecodeFunc()(o)
							if err != nil {
								logger.Println("decode err:", err.Error())
								reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
								return
							}
						}
						o, err = in.getDeCryptoFunc()(_key, o)
						if err != nil {
							logger.Println("decryption err:", err.Error())
							reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
							return
						}
						f.SetBytes(o)
						isDo = true
						continue
					}
					s, ok := f.Interface().([]string)
					if ok {
						if len(s) == 0 {
							continue
						}
						var e []string
						var o []byte
						var err error
						for _, _s := range s {
							if _s == "" {
								continue
							}
							o = []byte(_s)
							if needDecode {
								o, err = in.getDecodeFunc()(o)
								if err != nil {
									logger.Println("decode err:", err.Error())
									reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
									return
								}
							}
							o, err = in.getDeCryptoFunc()(_key, o)
							if err != nil {
								logger.Println("decryption err:", err.Error())
								reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
								return
							}
							e = append(e, string(o))
						}
						f.Set(reflect.ValueOf(e))
						isDo = true
						continue
					}

				case reflect.String:
					if f.String() == "" {
						continue
					}
					o := []byte(f.String())
					var err error
					if needDecode {
						o, err = in.getDecodeFunc()(o)
						if err != nil {
							logger.Println("decode err:", err.Error())
							reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
							return
						}
					}
					o, err = in.getDeCryptoFunc()(_key, o)
					if err != nil {
						logger.Println("decryption err:", err.Error())
						reflect.ValueOf(in).Elem().Set(reflect.ValueOf(c_in))
						return
					}
					f.SetString(string(o))
					isDo = true
				}
			}
		}
		if isDo == false {
			return
		}
		if in.getCryptoIndex() == -1 {
			in.setCryptoIndex(0)
		} else {
			in.setCryptoIndex(in.getCryptoIndex() - 1)
		}
	}
	return
}

func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Func, reflect.Map, reflect.Slice, reflect.Chan, reflect.Interface, reflect.UnsafePointer:
		return v.IsNil()
	case reflect.Array:
		z := true
		for i := 0; i < v.Len(); i++ {
			z = z && isZero(v.Index(i))
		}
		return z
	case reflect.Struct:
		z := true
		for i := 0; i < v.NumField(); i++ {
			z = z && isZero(v.Field(i))
		}
		return z
	}
	z := reflect.Zero(v.Type())
	return v.Interface() == z.Interface()
}
