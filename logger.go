package gostructcrypto

var logger Logger

type Logger interface {
	Print(v ...interface{})
	Println(v ...interface{})
}
