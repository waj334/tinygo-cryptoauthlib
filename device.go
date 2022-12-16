package cryptoauthlib

import "sync"

type Device struct {
	transport Transport
	mutex     sync.Mutex
}

func NewDevice(transport Transport) *Device {
	return &Device{
		transport: transport,
	}
}
