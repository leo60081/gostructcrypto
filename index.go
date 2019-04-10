package gostructcrypto

import (
	"gostructcrypto/aes"
	"log"
	"os"
	"sync"
)

var (
	lock       = new(sync.Mutex)
	defaultKey = []byte("hello_gostructcrypto")
)

func init() {
	logger = log.New(os.Stderr, "[GoSCrypt] ", log.LstdFlags)
	aes.SetLogger(logger)
}

func SetLogger(l Logger) {
	logger = l
	return
}

func SetGlobalKey(keyValue string) {
	lock.Lock()
	defer lock.Unlock()
	defaultKey = []byte(keyValue)
}

func GetGlobalKey() (key []byte) {
	lock.Lock()
	defer lock.Unlock()
	return defaultKey
}
