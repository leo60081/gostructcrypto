package aes

var (
	logger Logger
)

type Logger interface {
	Print(v ...interface{})
	Println(v ...interface{})
}

func SetLogger(l Logger) {
	logger = l
	return
}
