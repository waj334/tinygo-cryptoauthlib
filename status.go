package cryptoauthlib

const (
	StatusSuccess              Status = 0x00 //!< Function succeeded.
	StatusConfigZoneLocked     Status = 0x01
	StatusDataZoneLocked       Status = 0x02
	StatusInvalidPointer       Status = 0x03
	StatusInvalidLength        Status = 0x04
	StatusWakeFailed           Status = 0xD0 //!< response status byte indicates CheckMac failure (status byte = 0x01)
	StatusCheckmacVerifyFailed Status = 0xD1 //!< response status byte indicates CheckMac failure (status byte = 0x01)
	StatusParseError           Status = 0xD2 //!< response status byte indicates parsing error (status byte = 0x03)
	StatusCrc                  Status = 0xD4 //!< response status byte indicates DEVICE did not receive data properly (status byte = 0xFF)
	StatusUnknown              Status = 0xD5 //!< response status byte is unknown
	StatusEcc                  Status = 0xD6 //!< response status byte is ECC fault (status byte = 0x05)
	StatusSelftestError        Status = 0xD7 //!< response status byte is Self Test Error, chip in failure mode (status byte = 0x07)
	StatusFuncFail             Status = 0xE0 //!< Function could not execute due to incorrect condition / state.
	StatusGenFail              Status = 0xE1 //!< unspecified error
	StatusBadParam             Status = 0xE2 //!< bad argument (out of range, null pointer, etc.)
	StatusInvalidId            Status = 0xE3 //!< invalid device id, id not set
	StatusInvalidSize          Status = 0xE4 //!< Count value is out of range or greater than buffer size.
	StatusRxCrcError           Status = 0xE5 //!< CRC error in data received from device
	StatusRxFail               Status = 0xE6 //!< Timed out while waiting for response. Number of bytes received is > 0.
	StatusRxNoResponse         Status = 0xE7 //!< Not an error while the Command layer is polling for a command response.
	StatusResyncWithWakeup     Status = 0xE8 //!< Re-synchronization succeeded, but only after generating a Wake-up
	StatusParityError          Status = 0xE9 //!< for protocols needing parity
	StatusTxTimeout            Status = 0xEA //!< for Microchip PHY protocol, timeout on transmission waiting for master
	StatusRxTimeout            Status = 0xEB //!< for Microchip PHY protocol, timeout on receipt waiting for master
	StatusTooManyCommRetries   Status = 0xEC //!< Device did not respond too many times during a transmission. Could indicate no device present.
	StatusSmallBuffer          Status = 0xED //!< Supplied buffer is too small for data required
	StatusCommFail             Status = 0xF0 //!< Communication with device failed. Same as in hardware dependent modules.
	StatusTimeout              Status = 0xF1 //!< Timed out while waiting for response. Number of bytes received is 0.
	StatusBadOpcode            Status = 0xF2 //!< opcode is not supported by the device
	StatusWakeSuccess          Status = 0xF3 //!< received proper wake token
	StatusExecutionError       Status = 0xF4 //!< chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F)
	StatusUnimplemented        Status = 0xF5 //!< Function or some element of it hasn't been implemented yet
	StatusAssertFailure        Status = 0xF6 //!< Code failed run-time consistency check
	StatusTxFail               Status = 0xF7 //!< Failed to write
	StatusNotLocked            Status = 0xF8 //!< required zone was not locked
	StatusNoDevices            Status = 0xF9 //!< For protocols that support device discovery (kit protocol), no devices were found
	StatusHealthTestError      Status = 0xFA //!< random number generator health test error
	StatusAllocFailure         Status = 0xFB //!< Couldn't allocate required memory
	StatusUseFlagsConsumed     Status = 0xFC //!< Use flags on the device indicates its consumed fully
	StatusNotInitialized       Status = 0xFD //!< The library has not been initialized so the command could not be executed
)

type Status uint8

func (s Status) Error() string {
	switch s {
	case 0x00:
		return "function succeeded"
	case 0x01:
		return "config zone is locked"
	case 0x02:
		return "data zone is locked"
	case 0x03:
		return "invalid pointer"
	case 0x04:
		return "invalid length"
	case 0xD0:
		return "wake failed"
	case 0xD1:
		return "response status byte indicates CheckMac failure (status byte = 0x01)"
	case 0xD2:
		return "response status byte indicates parsing error (status byte = 0x03)"
	case 0xD4:
		return "response status byte indicates DEVICE did not receive data properly (status byte = 0xFF)"
	case 0xD5:
		return "response status byte is unknown"
	case 0xD6:
		return "response status byte is ECC fault (status byte = 0x05)"
	case 0xD7:
		return "response status byte is Self Test Error, chip in failure mode (status byte = 0x07)"
	case 0xE0:
		return "function could not execute due to incorrect condition / state."
	case 0xE1:
		return "unspecified error"
	case 0xE2:
		return "bad argument (out of range, null pointer, etc.)"
	case 0xE3:
		return "invalid device id, id not set"
	case 0xE4:
		return "count value is out of range or greater than buffer size."
	case 0xE5:
		return "crc error in data received from device"
	case 0xE6:
		return "timed out while waiting for response. Number of bytes received is > 0."
	case 0xE7:
		return "not an error while the Command layer is polling for a command response."
	case 0xE8:
		return "re-synchronization succeeded, but only after generating a Wake-up"
	case 0xE9:
		return "for protocols needing parity"
	case 0xEA:
		return "for Microchip PHY protocol, timeout on transmission waiting for master"
	case 0xEB:
		return "for Microchip PHY protocol, timeout on receipt waiting for master"
	case 0xEC:
		return "device did not respond too many times during a transmission. Could indicate no device present."
	case 0xED:
		return "supplied buffer is too small for data required"
	case 0xF0:
		return "communication with device failed. Same as in hardware dependent modules."
	case 0xF1:
		return "timed out while waiting for response. Number of bytes received is 0."
	case 0xF2:
		return "opcode is not supported by the device"
	case 0xF3:
		return "received proper wake token"
	case 0xF4:
		return "chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F)"
	case 0xF5:
		return "function or some element of it hasn't been implemented yet"
	case 0xF6:
		return "code failed run-time consistency check"
	case 0xF7:
		return "failed to write"
	case 0xF8:
		return "required zone was not locked"
	case 0xF9:
		return "for protocols that support device discovery (kit protocol), no devices were found"
	case 0xFA:
		return "random number generator health test error"
	case 0xFB:
		return "couldn't allocate required memory"
	case 0xFC:
		return "use flags on the device indicates its consumed fully"
	case 0xFD:
		return "the library has not been initialized so the command could not be executed"
	default:
		return "unknown status code"
	}
}

func mapCommandStatus(code byte) Status {
	switch code {
	case 0x00:
		return StatusSuccess
	case 0x01:
		return StatusCheckmacVerifyFailed
	case 0x03:
		return StatusParseError
	case 0x05:
		return StatusEcc
	case 0x07:
		return StatusSelftestError
	case 0x08:
		return StatusHealthTestError
	case 0x0F:
		return StatusExecutionError
	case 0x11:
		return StatusWakeSuccess
	case 0xFF:
		return StatusCrc
	default:
		return StatusGenFail
	}
}
