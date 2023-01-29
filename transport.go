package cryptoauthlib

type Transport interface {
	Receive(wordAddress byte, data []byte) (err error)
	Send(wordAddress byte, data []byte) (err error)
	WakeUp() (err error)
	Idle() (err error)
}
