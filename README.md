# GoStructCrypto

### 一個簡單使用 防呆的結構加密套件

## 特性
1. 使用簡單
2. AES ECB (預設) AES CBC 
3. Base64 編碼 (預設)
4. 支援自定義加密 （對稱式加密算法）
5. 支援自訂義編碼方法
6. 加密結構宣告維護簡易
７. 防呆設計 避免加解密次數不對等 導致的資料錯誤

## 簡易範例：
```
package main

import (
    "fmt"
	"encoding/json"	
	"github.com/leo60081/gostructcrypto"
)

type person struct {
	ID                  int
	Name                string
	Password            string   `crypto:"required"`
	Addr                string   `crypto:"required" encode:"required"`
	gostructcrypto.Crypto `-`
}

func main(){
	sample := &person{
		ID:       1234567890,
		Name:     "LeoChen",
		Password: "112233445566",
		Addr:     "100台北市中正區重慶南路一段122號",
	}
	
	gostructcrypto.SetGlobalKey("Happy_gostructcrypto")
	gostructcrypto.EnCryptoStruct(sample)
	b, _ := json.Marshal(sample)
	fmt.Printf("Plaintext: %+v\n", string(b))

	gostructcrypto.DecryptoStruct(sample)
	b, _ = json.Marshal(sample)
	fmt.Printf("Ciphertext: %+v\n", string(b))
}
```

## 進階範例：
```
package main

import (
    "fmt"
	"encoding/json"	
	"github.com/leo60081/gostructcrypto"
)

type person struct {
	ID                    int
	Name                  string
	Password              string    `crypto:"required"`
	Addr                  string    `crypto:"required" encode:"required"`
	Tags                  *[]string `crypto:"required" encode:"required"`
	Habbits               *habit
	gostructcrypto.Crypto `-`
}

type habit struct {
	Items                 []string `crypto:"required" encode:"required"`
	gostructcrypto.Crypto `-`
}

func main() {
	sample := &person{
		ID:       1234567890,
		Name:     "LeoChen",
		Password: "112233445566",
		Addr:     "100台北市中正區重慶南路一段122號",
		Tags: func() *[]string {
			s := []string{"abc", "efg", "hij"}
			return &s
		}(),
		Habbits: &habit{
			Items: []string{"coding", "golang", "sleeping"},
		},
	}

	sample.SetKey([]byte("Happy_gostructcrypto"))
	sample.Habbits.SetKey([]byte("qWrsXdRTb2WE$etpdlsDFTR2#!QA;?de"))
	cbc := aes.NewAseCBC([]byte("plqawskiedcvfgbr"))
	sample.Habbits.SetEnCryptoFunc(cbc.Encrypt)
	sample.Habbits.SetDeCryptoFunc(cbc.Decrypt)

	gostructcrypto.EnCryptoStruct(sample)
	b, _ := json.Marshal(sample)
	fmt.Printf("Plaintext: %+v\n", string(b))

	gostructcrypto.DecryptoStruct(sample)
	b, _ = json.Marshal(sample)
	fmt.Printf("Ciphertext: %+v\n", string(b))
}
```