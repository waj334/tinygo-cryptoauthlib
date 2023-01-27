package config

import (
	"reflect"
	"testing"
)

func TestConfigZone(t *testing.T) {
	expected := []byte{
		0xC0, //I2C_Address
		0x00, //Reserved
		0x00, //CountMatch - Disabled
		0x01, //ChipMode - Byte 85 is I2C address (if not 0), TTL is disabled, Watchdog is 1.3s, Clock divider is 0
		//SLOT CONFIGS
		0x8F, 0x20, //SLOT 0  - Secret key, GenKey enabled
		0xC4, 0x44, //SLOT 1  - ECDH key, Encrypted, Secret, SLOT 4 is encryption key, MAC Required and encrypt using Write command
		0x87, 0x20, //SLOT 2  - ECDH Key with output in clear, Secret, GenKey enabled
		0x87, 0x20, //SLOT 3  - ECDH Key with output in clear, Secret, GenKey enabled
		0x8F, 0x0F, //SLOT 4  - Secret key, SLOT 15 is encryption key, Clear text write enabled?
		0xC4, 0x00, //SLOT 5  - ECDH Key output in clear, Internal/external signatures disabled, Encrypted, secret
		0x9F, 0x0F, //SLOT 6  - Secret key, verification only, Secret
		0x82, 0x20, //SLOT 7  - Internal signing key only, Secret, GenKey enabled
		0x0F, 0x0F, //SLOT 8  - Private key, un-encrypted, Write permitted
		0xC4, 0x44, //SLOT 9  - Private key, un-encrypted, Write permitted
		0x0F, 0x0F, //SLOT 10 - Private key, un-encrypted, Write permitted
		0x0F, 0x0F, //SLOT 11 - Private key, un-encrypted, Write permitted
		0x0F, 0x0F, //SLOT 12 - Private key, un-encrypted, Write permitted
		0x0F, 0x0F, //SLOT 13 - Private key, un-encrypted, Write permitted
		0x0F, 0x0F, //SLOT 14 - Private key, un-encrypted, Write permitted
		0x0F, 0x0F, //SLOT 15 - Private key, un-encrypted, Write permitted
		//Counter[0]
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		//Counter[1]
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		//UseLock
		0x00,
		//VolatileKey Permission
		0x00,
		//SecureBoot
		0x00, 0x00,
		//KdfIvLoc
		0x00,
		//KdfIvStr
		0x00, 0x00,
		//Reserved
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		//UserExtra
		0x00,
		//UserExtraAdd
		0x00,
		//LockValue
		0xFF,
		//LockConfig
		0xFF,
		//SlotLocked
		0xFF, 0xFF,
		//ChipOptions
		0x06, 0x40,
		//X509format
		0x00, 0x00, 0x00, 0x00,
		//KeyConfig
		0x33, 0x00, //Key 0  - ECC Key, Public key enabled, P256, Lockable
		0x1C, 0x00, //Key 1  - Data, SHA, Not lockable
		//0001 0011
		0x13, 0x00, //Key 2  - Data, Public key used in verify, Not lockable
		0x13, 0x00, //Key 3  - Data, Public key used in verify, Not lockable
		0x7C, 0x00, //Key 4  - Data, SHA or other, Lockable random nonce
		0x18, 0x00, //Key 5  - Data, AES, Not lockable
		0x3C, 0x00, //Key 6  - Data, SHA or other, Lockable
		0x33, 0x00, //Key 7  - ECC Key, Public key enabled, P256, Lockable
		0x3C, 0x00, //Key 8  - Data, SHA or other, Lockable
		0x3C, 0x00, //Key 9  - Data, SHA or other, Lockable
		0x3C, 0x00, //Key 10 - Data, SHA or other, Lockable
		0x30, 0x00, //Key 11 - Data, P256, Lockable
		0x3C, 0x00, //Key 12 - Data, SHA or other, Lockable
		0x3C, 0x00, //Key 13 - Data, SHA or other, Lockable
		0x3C, 0x00, //Key 14 - Data, SHA or other, Lockable
		0x30, 0x00, //Key 15 - Data, P256, Lockable
	}

	// Recreate known good config
	config := ConfigZone{
		I2CAddress: 0xC0,
		CountMatch: CountMatchDisabled,
		ChipMode:   I2CAddressUserExtraAdd | TTLDisabled | Watchdog1p3 | ClockDivider00,
		SlotConfigs: [16]SlotConfig{
			{ //0
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key0,
				WriteConfig: GenKeyPermitted,
			},
			{ //1
				ReadKey:     ECDHPermitted,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadEnabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key4,
				WriteConfig: Encrypt,
			},
			{ //2
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key0,
				WriteConfig: GenKeyPermitted,
			},
			{ //3
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key0,
				WriteConfig: GenKeyPermitted,
			},
			{ //4
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key15,
				WriteConfig: Always,
			},
			{ //5
				ReadKey:     ECDHPermitted,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadEnabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key0,
				WriteConfig: Always,
			},
			{ //6
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacEnabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key15,
				WriteConfig: GenKeyNotPermitted,
			},
			{ //7
				ReadKey:     InternalSignaturesEnabled,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key0,
				WriteConfig: GenKeyPermitted,
			},
			{ //8
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretDisabled,
				WriteKey:    Key15,
				WriteConfig: Always,
			},
			{ //9
				ReadKey:     ECDHPermitted,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadEnabled,
				IsSecret:    IsSecretEnabled,
				WriteKey:    Key4,
				WriteConfig: PrivWritePermitted,
			},
			{ //10
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretDisabled,
				WriteKey:    Key15,
				WriteConfig: Always,
			},
			{ //11
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretDisabled,
				WriteKey:    Key15,
				WriteConfig: Always,
			},
			{ //12
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretDisabled,
				WriteKey:    Key15,
				WriteConfig: Always,
			},
			{ //13
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretDisabled,
				WriteKey:    Key15,
				WriteConfig: Always,
			},
			{ //14
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretDisabled,
				WriteKey:    Key15,
				WriteConfig: Always,
			},
			{ //15
				ReadKey:     ExternalSignaturesEnabled | InternalSignaturesEnabled | ECDHPermitted | ECDHMasterSecretToSlot,
				NoMac:       NoMacDisabled,
				LimitedUse:  LimitedUseDisabled,
				EncryptRead: EncryptReadDisabled,
				IsSecret:    IsSecretDisabled,
				WriteKey:    Key15,
				WriteConfig: Always,
			},
		},
		Counter0:              [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00},
		Counter1:              [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00},
		UseLock:               UseLockDisabled,
		VolatileKeyPermission: VolatileKeyPermitDisabled,
		SecureBoot: SecureBootConfig{
			Mode:       SecureBootDisabled,
			Persistent: PersistentDisabled,
			RandNonce:  RandNonceDisabled,
			SigDigSlot: SigDigSlot0,
			PubKeySlot: SecureBootPubKeySlot0,
		},
		KdfIvLoc:     0x00,
		KdfIvStr:     [2]byte{0x00, 0x00},
		UserExtra:    0x00,
		UserExtraAdd: 0x00,
		SlotLocked:   [2]byte{0xFF, 0xFF},
		ChipOptions: ChipOptionsConfig{
			PowerOnSelfTest: PowerOnSelfTestDisabled,
			IOProtection:    IOProtectionKeyEnabled,
			KdfAes:          KdfAesEnabled,
			ProtectionBits:  ECDHInClear | KDFInClear,
			IOProtectionKey: IOProtectionKey4,
		},
		X509Format: [4]byte{0x00, 0x00, 0x00, 0x00},
		KeyConfigs: [16]KeyConfig{
			{
				Private:           PrivateEnabled,
				PubInfo:           CanGeneratePublicEnabled,
				KeyType:           P256Key,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableDisabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateEnabled,
				PubInfo:           RequirePublicKeyVerificationEnabled,
				KeyType:           P256Key,
				Lockable:          LockableDisabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateEnabled,
				PubInfo:           RequirePublicKeyVerificationEnabled,
				KeyType:           P256Key,
				Lockable:          LockableDisabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredEnabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           AESKey,
				Lockable:          LockableDisabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateEnabled,
				PubInfo:           CanGeneratePublicEnabled,
				KeyType:           P256Key,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           P256Key,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           SHAKey,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
			{
				Private:           PrivateDisabled,
				PubInfo:           RequirePublicKeyVerificationDisabled,
				KeyType:           P256Key,
				Lockable:          LockableEnabled,
				ReqRandom:         RandomNonceRequiredDisabled,
				ReqAuth:           AuthRequiredDisabled,
				AuthKey:           AuthKey0,
				PersistentDisable: PersistentLatchRequiredDisabled,
				X509Id:            0x00,
			},
		},
	}

	configBytes := config.Bytes()
	if !reflect.DeepEqual(configBytes, expected) {
		t.Errorf("\nexpected:\t% +X\n got:\t\t% +X", expected, configBytes)
	}
}
