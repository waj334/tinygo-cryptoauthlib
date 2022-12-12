package cryptoauthlib

type Device struct {
	transport Transport
}

func NewDevice(transport Transport) *Device {
	return &Device{
		transport: transport,
	}
}
