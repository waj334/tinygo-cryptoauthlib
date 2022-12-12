package cryptoauthlib

import (
	"bytes"
	"sync"
	"time"
)

type I2C interface {
	ReadRegister(addr uint8, r uint8, buf []byte) error
	WriteRegister(addr uint8, r uint8, buf []byte) error
	Tx(addr uint16, w, r []byte) error
	SetBaudRate(br uint32)
}

type i2cTransport struct {
	deviceAddress uint8
	bus           I2C
	mutex         sync.Mutex
}

func NewI2CTransport(deviceAddress uint8, bus I2C) Transport {
	return &i2cTransport{
		deviceAddress: deviceAddress >> 1,
		bus:           bus,
	}
}

func (i *i2cTransport) Receive(wordAddress byte, data []byte) (err error) {
	return i.bus.ReadRegister(i.deviceAddress, wordAddress, data)
}

func (i *i2cTransport) ReceiveRaw(data []byte) (err error) {
	return i.bus.Tx(uint16(i.deviceAddress), nil, data)
}

func (i *i2cTransport) Send(wordAddress byte, data []byte) (err error) {
	return i.bus.WriteRegister(i.deviceAddress, wordAddress, data)
}

func (i *i2cTransport) WakeUp() (err error) {
	for retry := 0; retry < 20; retry++ {
		// Set the bus speed to slow af. The device requires the SDA pin to be low for a specific amount of time
		i.bus.SetBaudRate(100_000)

		// Send zeros to wake the device
		i.bus.WriteRegister(0x00, 0x00, []byte{0x00})

		// Reset the bus speed
		// TODO: Reset this to what was originally configured
		i.bus.SetBaudRate(1_000_000)

		//delay
		time.Sleep(time.Microsecond * 1500)

		// Receive wake status
		var wake [4]byte
		if err = i.bus.ReadRegister(i.deviceAddress, 0x00, wake[:]); err != nil {
			continue
		}

		// Check the wake status value
		expectedResponse := []byte{0x04, 0x11, 0x33, 0x43}
		selftestFailResp := []byte{0x04, 0x07, 0xC4, 0x40}

		if bytes.Equal(wake[:], expectedResponse) {
			return nil
		} else if !bytes.Equal(wake[:], selftestFailResp) {
			err = StatusSelftestError
			break
		}
	}

	return StatusWakeFailed
}
