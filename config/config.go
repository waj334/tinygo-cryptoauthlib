package config

import "bytes"

const (
	ConfigDataSize = 128 - 16 // The first 16 bytes of the config zone is readonly
)

type KeyId uint8

const (
	Key0 KeyId = iota
	Key1
	Key2
	Key3
	Key4
	Key5
	Key6
	Key7
	Key8
	Key9
	Key10
	Key11
	Key12
	Key13
	Key14
	Key15
	KeyMax
)

type CountMatchKeyId uint8

const (
	CountMatchDisabled CountMatchKeyId = 0
	CountMatchKey0     CountMatchKeyId = 0b0000_0001
	CountMatchKey1     CountMatchKeyId = 0b0001_0001
	CountMatchKey2     CountMatchKeyId = 0b0010_0001
	CountMatchKey3     CountMatchKeyId = 0b0011_0001
	CountMatchKey4     CountMatchKeyId = 0b0100_0001
	CountMatchKey5     CountMatchKeyId = 0b0101_0001
	CountMatchKey6     CountMatchKeyId = 0b0110_0001
	CountMatchKey7     CountMatchKeyId = 0b0111_0001
	CountMatchKey8     CountMatchKeyId = 0b1000_0001
	CountMatchKey9     CountMatchKeyId = 0b1001_0001
	CountMatchKey10    CountMatchKeyId = 0b1010_0001
	CountMatchKey11    CountMatchKeyId = 0b1011_0001
	CountMatchKey12    CountMatchKeyId = 0b1100_0001
	CountMatchKey13    CountMatchKeyId = 0b1101_0001
	CountMatchKey14    CountMatchKeyId = 0b1110_0001
	CountMatchKey15    CountMatchKeyId = 0b1111_0001
)

type ChipModeConfig uint8

const (
	I2CAddressDefault      ChipModeConfig = 0b0000_0000
	I2CAddressUserExtraAdd ChipModeConfig = 0b0000_0001

	TTLEnabled  ChipModeConfig = 0b0000_0010
	TTLDisabled ChipModeConfig = 0b0000_0000

	Watchdog1p3  ChipModeConfig = 0b0000_0000
	Watchdog10p0 ChipModeConfig = 0b0000_0100

	ClockDivider00 ChipModeConfig = 0b0000_0000
	ClockDivider0D ChipModeConfig = 0b0110_1000
	ClockDivider05 ChipModeConfig = 0b0010_1000
)

type UseLockSlot uint8

const (
	UseLockDisabled UseLockSlot = 0
	UseLockSlot0    UseLockSlot = 0b0000_1010
	UseLockSlot1    UseLockSlot = 0b0001_1010
	UseLockSlot2    UseLockSlot = 0b0010_1010
	UseLockSlot3    UseLockSlot = 0b0011_1010
	UseLockSlot4    UseLockSlot = 0b0100_1010
	UseLockSlot5    UseLockSlot = 0b0101_1010
	UseLockSlot6    UseLockSlot = 0b0110_1010
	UseLockSlot7    UseLockSlot = 0b0111_1010
	UseLockSlot8    UseLockSlot = 0b1000_1010
	UseLockSlot9    UseLockSlot = 0b1001_1010
	UseLockSlot10   UseLockSlot = 0b1010_1010
	UseLockSlot11   UseLockSlot = 0b1011_1010
	UseLockSlot12   UseLockSlot = 0b1100_1010
	UseLockSlot13   UseLockSlot = 0b1101_1010
	UseLockSlot14   UseLockSlot = 0b1110_1010
	UseLockSlot15   UseLockSlot = 0b1111_1010
)

type VolatileKeyPermitSlot uint8

const (
	VolatileKeyPermitDisabled VolatileKeyPermitSlot = 0
	VolatileKeyPermitSlot0    VolatileKeyPermitSlot = 0b1000_0000
	VolatileKeyPermitSlot1    VolatileKeyPermitSlot = 0b1000_0001
	VolatileKeyPermitSlot2    VolatileKeyPermitSlot = 0b1000_0010
	VolatileKeyPermitSlot3    VolatileKeyPermitSlot = 0b1000_0011
	VolatileKeyPermitSlot4    VolatileKeyPermitSlot = 0b1000_0100
	VolatileKeyPermitSlot5    VolatileKeyPermitSlot = 0b1000_0101
	VolatileKeyPermitSlot6    VolatileKeyPermitSlot = 0b1000_0110
	VolatileKeyPermitSlot7    VolatileKeyPermitSlot = 0b1000_0111
	VolatileKeyPermitSlot8    VolatileKeyPermitSlot = 0b1000_1000
	VolatileKeyPermitSlot9    VolatileKeyPermitSlot = 0b1000_1001
	VolatileKeyPermitSlot10   VolatileKeyPermitSlot = 0b1000_1010
	VolatileKeyPermitSlot11   VolatileKeyPermitSlot = 0b1000_1011
	VolatileKeyPermitSlot12   VolatileKeyPermitSlot = 0b1000_1100
	VolatileKeyPermitSlot13   VolatileKeyPermitSlot = 0b1000_1101
	VolatileKeyPermitSlot14   VolatileKeyPermitSlot = 0b1000_1110
	VolatileKeyPermitSlot15   VolatileKeyPermitSlot = 0b1000_1111
)

type ReadKeyConfig uint8

const (
	CheckMacSourceEnabled ReadKeyConfig = 0

	ExternalSignaturesEnabled  ReadKeyConfig = 0b0000_0001
	ExternalSignaturesDisabled ReadKeyConfig = 0

	InternalSignaturesEnabled  ReadKeyConfig = 0b0000_0010
	InternalSignaturesDisabled ReadKeyConfig = 0

	ECDHPermitted    ReadKeyConfig = 0b0000_0100
	ECDHNotPermitted ReadKeyConfig = 0

	ECDHMasterSecretToSlot  ReadKeyConfig = 0b0000_1000
	ECDHMasterSecretInClear ReadKeyConfig = 0
)

type MacConfig uint8

const (
	NoMacEnabled  MacConfig = 0b0001_0000
	NoMacDisabled MacConfig = 0
)

type LimitedUseConfig uint8

const (
	LimitedUseEnabled  LimitedUseConfig = 0b0010_0000
	LimitedUseDisabled LimitedUseConfig = 0
)

type EncryptReadConfig uint8

const (
	EncryptReadEnabled  EncryptReadConfig = 0b0100_0000
	EncryptReadDisabled EncryptReadConfig = 0
)

type IsSecretConfig uint8

const (
	IsSecretEnabled  IsSecretConfig = 0b1000_0000
	IsSecretDisabled IsSecretConfig = 0
)

type WriteConfigConfig uint8

const (
	Always     WriteConfigConfig = 0b0000_0000
	PubInvalid WriteConfigConfig = 0b0001_0000
	Never      WriteConfigConfig = 0b0010_0000
	Encrypt    WriteConfigConfig = 0b0100_0000

	DeriveKeyNotPermitted WriteConfigConfig = 0
	DeriveKeyPermitted    WriteConfigConfig = 0b0010_0000
	AuthMacRequired       WriteConfigConfig = 0b1000_0000
	SourceIsTarget        WriteConfigConfig = 0
	SourceIsParent        WriteConfigConfig = 0b0001_0000

	GenKeyNotPermitted WriteConfigConfig = 0
	GenKeyPermitted    WriteConfigConfig = 0b0010_0000

	PrivWriteNotPermitted WriteConfigConfig = 0
	PrivWritePermitted    WriteConfigConfig = 0b0100_0000
)

type SecureBootModeConfig uint8

const (
	SecureBootDisabled SecureBootModeConfig = 0
	FullSecureBoot     SecureBootModeConfig = 0b0000_0001
	StoreSignature     SecureBootModeConfig = 0b0000_0010
	StoreDigest        SecureBootModeConfig = 0b0000_0011
)

type SecureBootPersistentConfig uint8

const (
	PersistentEnabled  SecureBootPersistentConfig = 0b0000_1000
	PersistentDisabled SecureBootPersistentConfig = 0b0000_0000
)

type SecureBootBootRandNonceConfig uint8

const (
	RandNonceEnabled  SecureBootBootRandNonceConfig = 0b0001_0000
	RandNonceDisabled SecureBootBootRandNonceConfig = 0b0000_0000
)

type SecureBootSigDigSlot uint8

const (
	SigDigSlot0  SecureBootSigDigSlot = 0b0000_0000
	SigDigSlot1  SecureBootSigDigSlot = 0b0000_0001
	SigDigSlot2  SecureBootSigDigSlot = 0b0000_0010
	SigDigSlot3  SecureBootSigDigSlot = 0b0000_0011
	SigDigSlot4  SecureBootSigDigSlot = 0b0000_0100
	SigDigSlot5  SecureBootSigDigSlot = 0b0000_0101
	SigDigSlot6  SecureBootSigDigSlot = 0b0000_0110
	SigDigSlot7  SecureBootSigDigSlot = 0b0000_0111
	SigDigSlot8  SecureBootSigDigSlot = 0b0000_1000
	SigDigSlot9  SecureBootSigDigSlot = 0b0000_1001
	SigDigSlot10 SecureBootSigDigSlot = 0b0000_1010
	SigDigSlot11 SecureBootSigDigSlot = 0b0000_1011
	SigDigSlot12 SecureBootSigDigSlot = 0b0000_1100
	SigDigSlot13 SecureBootSigDigSlot = 0b0000_1101
	SigDigSlot14 SecureBootSigDigSlot = 0b0000_1110
	SigDigSlot15 SecureBootSigDigSlot = 0b0000_1111
)

type SecureBootPubKeySlot uint8

const (
	SecureBootPubKeySlot0  SecureBootPubKeySlot = 0b0000_0000
	SecureBootPubKeySlot1  SecureBootPubKeySlot = 0b0001_0000
	SecureBootPubKeySlot2  SecureBootPubKeySlot = 0b0010_0000
	SecureBootPubKeySlot3  SecureBootPubKeySlot = 0b0011_0000
	SecureBootPubKeySlot4  SecureBootPubKeySlot = 0b0100_0000
	SecureBootPubKeySlot5  SecureBootPubKeySlot = 0b0101_0000
	SecureBootPubKeySlot6  SecureBootPubKeySlot = 0b0110_0000
	SecureBootPubKeySlot7  SecureBootPubKeySlot = 0b0111_0000
	SecureBootPubKeySlot8  SecureBootPubKeySlot = 0b1000_0000
	SecureBootPubKeySlot9  SecureBootPubKeySlot = 0b1001_0000
	SecureBootPubKeySlot10 SecureBootPubKeySlot = 0b1010_0000
	SecureBootPubKeySlot11 SecureBootPubKeySlot = 0b1011_0000
	SecureBootPubKeySlot12 SecureBootPubKeySlot = 0b1100_0000
	SecureBootPubKeySlot13 SecureBootPubKeySlot = 0b1101_0000
	SecureBootPubKeySlot14 SecureBootPubKeySlot = 0b1110_0000
	SecureBootPubKeySlot15 SecureBootPubKeySlot = 0b1111_0000
)

type PowerOnSelfTestConfig uint8

const (
	PowerOnSelfTestEnabled  PowerOnSelfTestConfig = 0b0000_0001
	PowerOnSelfTestDisabled PowerOnSelfTestConfig = 0b0000_0000
)

type IOProtectionKeyConfig uint8

const (
	IOProtectionKeyEnabled  IOProtectionKeyConfig = 0b0000_0010
	IOProtectionKeyDisabled IOProtectionKeyConfig = 0b0000_0000
)

type KdfAesEnabledConfig uint8

const (
	KdfAesEnabled  KdfAesEnabledConfig = 0b0000_0100
	KdfAesDisabled KdfAesEnabledConfig = 0b0000_0000
)

type ProtectionBitsConfig uint8

const (
	ECDHInClear         ProtectionBitsConfig = 0b0000_0000
	ECDHEncrypt         ProtectionBitsConfig = 0b0000_0001
	ECDHOutputForbidden ProtectionBitsConfig = 0b0000_0010

	KDFInClear         ProtectionBitsConfig = 0b0000_0000
	KDFEncrypt         ProtectionBitsConfig = 0b0000_0100
	KDFOutputForbidden ProtectionBitsConfig = 0b0000_1000
)

type IOProtectionKeyId uint8

const (
	IOProtectionKey0  IOProtectionKeyId = 0b0000_0000
	IOProtectionKey1  IOProtectionKeyId = 0b0001_0000
	IOProtectionKey2  IOProtectionKeyId = 0b0010_0000
	IOProtectionKey3  IOProtectionKeyId = 0b0011_0000
	IOProtectionKey4  IOProtectionKeyId = 0b0100_0000
	IOProtectionKey5  IOProtectionKeyId = 0b0101_0000
	IOProtectionKey6  IOProtectionKeyId = 0b0110_0000
	IOProtectionKey7  IOProtectionKeyId = 0b0111_0000
	IOProtectionKey8  IOProtectionKeyId = 0b1000_0000
	IOProtectionKey9  IOProtectionKeyId = 0b1001_0000
	IOProtectionKey10 IOProtectionKeyId = 0b1010_0000
	IOProtectionKey11 IOProtectionKeyId = 0b1011_0000
	IOProtectionKey12 IOProtectionKeyId = 0b1100_0000
	IOProtectionKey13 IOProtectionKeyId = 0b1101_0000
	IOProtectionKey14 IOProtectionKeyId = 0b1110_0000
	IOProtectionKey15 IOProtectionKeyId = 0b1111_0000
)

type PrivateConfig uint8

const (
	PrivateEnabled  PrivateConfig = 0b0000_0001
	PrivateDisabled PrivateConfig = 0b0000_0000
)

type PubInfoConfig uint8

const (
	CanGeneratePublicEnabled  PubInfoConfig = 0b0000_0010
	CanGeneratePublicDisabled PubInfoConfig = 0b0000_0000

	RequirePublicKeyVerificationEnabled  PubInfoConfig = 0b0000_0010
	RequirePublicKeyVerificationDisabled PubInfoConfig = 0b0000_0000

	KdfPermitted    PubInfoConfig = 0b0000_0010
	KdfNotPermitted PubInfoConfig = 0b0000_0000
)

type KeyType uint8

const (
	P256Key KeyType = 0b0001_0000
	AESKey  KeyType = 0b0001_1000
	SHAKey  KeyType = 0b0001_1100
)

type LockableConfig uint8

const (
	LockableEnabled  LockableConfig = 0b0010_0000
	LockableDisabled LockableConfig = 0b0000_0000
)

type ReqRandomConfig uint8

const (
	RandomNonceRequiredEnabled  = 0b0100_0000
	RandomNonceRequiredDisabled = 0b0000_0000
)

type ReqAuthConfig uint8

const (
	AuthRequiredEnabled  ReqAuthConfig = 0b1000_0000
	AuthRequiredDisabled ReqAuthConfig = 0b0000_0000
)

type AuthKeyConfig uint8

const (
	AuthKey0  = AuthKeyConfig(Key0)
	AuthKey1  = AuthKeyConfig(Key1)
	AuthKey2  = AuthKeyConfig(Key2)
	AuthKey3  = AuthKeyConfig(Key3)
	AuthKey4  = AuthKeyConfig(Key4)
	AuthKey5  = AuthKeyConfig(Key5)
	AuthKey6  = AuthKeyConfig(Key6)
	AuthKey7  = AuthKeyConfig(Key7)
	AuthKey8  = AuthKeyConfig(Key8)
	AuthKey9  = AuthKeyConfig(Key9)
	AuthKey10 = AuthKeyConfig(Key10)
	AuthKey11 = AuthKeyConfig(Key11)
	AuthKey12 = AuthKeyConfig(Key12)
	AuthKey13 = AuthKeyConfig(Key13)
	AuthKey14 = AuthKeyConfig(Key14)
	AuthKey15 = AuthKeyConfig(Key15)
)

type PersistentDisableConfig uint8

const (
	PersistentLatchRequiredEnabled  PersistentDisableConfig = 0b0001_0000
	PersistentLatchRequiredDisabled PersistentDisableConfig = 0b0000_0000
)

type SlotConfig struct {
	ReadKey     ReadKeyConfig
	NoMac       MacConfig
	LimitedUse  LimitedUseConfig
	EncryptRead EncryptReadConfig
	IsSecret    IsSecretConfig
	WriteKey    KeyId
	WriteConfig WriteConfigConfig
}

func (s *SlotConfig) Bytes() (data []byte) {
	if s.WriteKey < 0 || s.WriteKey > KeyMax {
		panic("SlotConfig: Invalid Write Key")
	}

	return []byte{
		byte(s.ReadKey) | byte(s.NoMac) | byte(s.LimitedUse) | byte(s.EncryptRead) | byte(s.IsSecret),
		byte(s.WriteKey) | byte(s.WriteConfig),
	}
}

type SecureBootConfig struct {
	Mode       SecureBootModeConfig
	Persistent SecureBootPersistentConfig
	RandNonce  SecureBootBootRandNonceConfig
	SigDigSlot SecureBootSigDigSlot
	PubKeySlot SecureBootPubKeySlot
}

func (s *SecureBootConfig) Bytes() (data []byte) {
	data = make([]byte, 2)
	data[0] = byte(s.Mode) | byte(s.Persistent) | byte(s.RandNonce)
	data[1] = byte(s.SigDigSlot) | byte(s.PubKeySlot)
	return
}

type ChipOptionsConfig struct {
	PowerOnSelfTest PowerOnSelfTestConfig
	IOProtection    IOProtectionKeyConfig
	KdfAes          KdfAesEnabledConfig
	ProtectionBits  ProtectionBitsConfig
	IOProtectionKey IOProtectionKeyId
}

func (c *ChipOptionsConfig) Bytes() (data []byte) {
	data = make([]byte, 2)
	data[0] = byte(c.PowerOnSelfTest) | byte(c.IOProtection) | byte(c.KdfAes)
	data[1] = byte(c.ProtectionBits) | byte(c.IOProtectionKey)
	return
}

type KeyConfig struct {
	Private           PrivateConfig
	PubInfo           PubInfoConfig
	KeyType           KeyType
	Lockable          LockableConfig
	ReqRandom         ReqRandomConfig
	ReqAuth           ReqAuthConfig
	AuthKey           AuthKeyConfig
	PersistentDisable PersistentDisableConfig
	X509Id            byte
}

func (k *KeyConfig) Bytes() (data []byte) {
	data = make([]byte, 2)
	data[0] = byte(k.Private) | byte(k.PubInfo) | byte(k.KeyType) | byte(k.Lockable) | byte(k.ReqRandom) | byte(k.ReqAuth)
	data[1] = byte(k.AuthKey) | byte(k.PersistentDisable) | ((k.X509Id << 6) & 0b1100_0000)
	return
}

type ConfigZone struct {
	I2CAddress            byte
	CountMatch            CountMatchKeyId
	ChipMode              ChipModeConfig
	SlotConfigs           [16]SlotConfig
	Counter0              [8]byte
	Counter1              [8]byte
	UseLock               UseLockSlot
	VolatileKeyPermission VolatileKeyPermitSlot
	SecureBoot            SecureBootConfig
	KdfIvLoc              byte
	KdfIvStr              [2]byte
	UserExtra             byte
	UserExtraAdd          byte
	SlotLocked            [2]byte
	ChipOptions           ChipOptionsConfig
	X509Format            [4]byte
	KeyConfigs            [16]KeyConfig
}

func (c *ConfigZone) Bytes() (data []byte) {
	data = make([]byte, 0, ConfigDataSize)
	buf := bytes.NewBuffer(data)

	buf.WriteByte(c.I2CAddress)
	buf.WriteByte(0) // Skip
	buf.WriteByte(byte(c.CountMatch))
	buf.WriteByte(byte(c.ChipMode))

	for _, slotConfig := range c.SlotConfigs {
		buf.Write(slotConfig.Bytes())
	}

	buf.Write(c.Counter0[:])
	buf.Write(c.Counter1[:])
	buf.WriteByte(byte(c.UseLock))
	buf.WriteByte(byte(c.VolatileKeyPermission))
	buf.Write(c.SecureBoot.Bytes())
	buf.WriteByte(c.KdfIvLoc)
	buf.Write(c.KdfIvStr[:])

	// Skip the next 9 bytes
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(0)

	buf.WriteByte(c.UserExtra)
	buf.WriteByte(c.UserExtraAdd)
	buf.WriteByte(0xFF) // Skip
	buf.WriteByte(0xFF) // Skip
	buf.Write(c.SlotLocked[:])
	buf.Write(c.ChipOptions.Bytes())
	buf.Write(c.X509Format[:])

	for _, keyConfig := range c.KeyConfigs {
		buf.Write(keyConfig.Bytes())
	}

	return buf.Bytes()
}
