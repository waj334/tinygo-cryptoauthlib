package cryptoauthlib

const (
	ATCA_AES_ENABLE_EN_SHIFT uint32 = 0
	ATCA_AES_ENABLE_EN_MASK  uint32 = 0x01 << ATCA_AES_ENABLE_EN_SHIFT

	/* I2C */
	ATCA_I2C_ENABLE_EN_SHIFT uint32 = 0
	ATCA_I2C_ENABLE_EN_MASK  uint32 = 0x01 << ATCA_I2C_ENABLE_EN_SHIFT

	/* Counter Match Feature */
	ATCA_COUNTER_MATCH_EN_SHIFT  uint32 = 0
	ATCA_COUNTER_MATCH_EN_MASK   uint32 = 0x01 << ATCA_COUNTER_MATCH_EN_SHIFT
	ATCA_COUNTER_MATCH_KEY_SHIFT uint32 = 4
	ATCA_COUNTER_MATCH_KEY_MASK  uint32 = 0x0F << ATCA_COUNTER_MATCH_KEY_SHIFT

	/* ChipMode */
	ATCA_CHIP_MODE_I2C_EXTRA_SHIFT uint32 = 0
	ATCA_CHIP_MODE_I2C_EXTRA_MASK  uint32 = 0x01 << ATCA_CHIP_MODE_I2C_EXTRA_SHIFT
	ATCA_CHIP_MODE_TTL_EN_SHIFT    uint32 = 1
	ATCA_CHIP_MODE_TTL_EN_MASK     uint32 = 0x01 << ATCA_CHIP_MODE_TTL_EN_SHIFT
	ATCA_CHIP_MODE_WDG_LONG_SHIFT  uint32 = 2
	ATCA_CHIP_MODE_WDG_LONG_MASK   uint32 = 0x01 << ATCA_CHIP_MODE_WDG_LONG_SHIFT
	ATCA_CHIP_MODE_CLK_DIV_SHIFT   uint32 = 3
	ATCA_CHIP_MODE_CLK_DIV_MASK    uint32 = 0x1F << ATCA_CHIP_MODE_CLK_DIV_SHIFT

	/* General Purpose Slot Config (Not ECC Private Keys) */
	ATCA_SLOT_CONFIG_READKEY_SHIFT        uint32 = 0
	ATCA_SLOT_CONFIG_READKEY_MASK         uint32 = 0x0F << ATCA_SLOT_CONFIG_READKEY_SHIFT
	ATCA_SLOT_CONFIG_NOMAC_SHIFT          uint32 = 4
	ATCA_SLOT_CONFIG_NOMAC_MASK           uint32 = 0x01 << ATCA_SLOT_CONFIG_NOMAC_SHIFT
	ATCA_SLOT_CONFIG_LIMITED_USE_SHIFT    uint32 = 5
	ATCA_SLOT_CONFIG_LIMITED_USE_MASK     uint32 = 0x01 << ATCA_SLOT_CONFIG_LIMITED_USE_SHIFT
	ATCA_SLOT_CONFIG_ENCRYPTED_READ_SHIFT uint32 = 6
	ATCA_SLOT_CONFIG_ENCRYPTED_READ_MASK  uint32 = 0x01 << ATCA_SLOT_CONFIG_ENCRYPTED_READ_SHIFT
	ATCA_SLOT_CONFIG_IS_SECRET_SHIFT      uint32 = 7
	ATCA_SLOT_CONFIG_IS_SECRET_MASK       uint32 = 0x01 << ATCA_SLOT_CONFIG_IS_SECRET_SHIFT
	ATCA_SLOT_CONFIG_WRITE_KEY_SHIFT      uint32 = 8
	ATCA_SLOT_CONFIG_WRITE_KEY_MASK       uint32 = 0x0F << ATCA_SLOT_CONFIG_WRITE_KEY_SHIFT
	ATCA_SLOT_CONFIG_WRITE_CONFIG_SHIFT   uint32 = 12
	ATCA_SLOT_CONFIG_WRITE_CONFIG_MASK    uint32 = 0x0F << ATCA_SLOT_CONFIG_WRITE_CONFIG_SHIFT

	/* Slot Config for ECC Private Keys */
	ATCA_SLOT_CONFIG_EXT_SIG_SHIFT    uint32 = 0
	ATCA_SLOT_CONFIG_EXT_SIG_MASK     uint32 = 0x01 << ATCA_SLOT_CONFIG_EXT_SIG_SHIFT
	ATCA_SLOT_CONFIG_INT_SIG_SHIFT    uint32 = 1
	ATCA_SLOT_CONFIG_INT_SIG_MASK     uint32 = 0x01 << ATCA_SLOT_CONFIG_INT_SIG_SHIFT
	ATCA_SLOT_CONFIG_ECDH_SHIFT       uint32 = 2
	ATCA_SLOT_CONFIG_ECDH_MASK        uint32 = 0x01 << ATCA_SLOT_CONFIG_ECDH_SHIFT
	ATCA_SLOT_CONFIG_WRITE_ECDH_SHIFT uint32 = 3
	ATCA_SLOT_CONFIG_WRITE_ECDH_MASK  uint32 = 0x01 << ATCA_SLOT_CONFIG_WRITE_ECDH_SHIFT
	ATCA_SLOT_CONFIG_GEN_KEY_SHIFT    uint32 = 8
	ATCA_SLOT_CONFIG_GEN_KEY_MASK     uint32 = 0x01 << ATCA_SLOT_CONFIG_GEN_KEY_SHIFT
	ATCA_SLOT_CONFIG_PRIV_WRITE_SHIFT uint32 = 9
	ATCA_SLOT_CONFIG_PRIV_WRITE_MASK  uint32 = 0x01 << ATCA_SLOT_CONFIG_PRIV_WRITE_SHIFT

	/* Use Lock */
	ATCA_USE_LOCK_ENABLE_SHIFT uint32 = 0
	ATCA_USE_LOCK_ENABLE_MASK  uint32 = 0x0F << ATCA_USE_LOCK_ENABLE_SHIFT
	ATCA_USE_LOCK_KEY_SHIFT    uint32 = 4
	ATCA_USE_LOCK_KEY_MASK     uint32 = 0x0F << ATCA_USE_LOCK_KEY_SHIFT

	/* Voltatile Key Permission */
	ATCA_VOL_KEY_PERM_SLOT_SHIFT uint32 = 0
	ATCA_VOL_KEY_PERM_SLOT_MASK  uint32 = 0x0F << ATCA_VOL_KEY_PERM_SLOT_SHIFT
	ATCA_VOL_KEY_PERM_EN_SHIFT   uint32 = 7
	ATCA_VOL_KEY_PERM_EN_MASK    uint32 = 0x01 << ATCA_VOL_KEY_PERM_EN_SHIFT

	/* Secure Boot */
	ATCA_SECURE_BOOT_MODE_SHIFT       uint32 = 0
	ATCA_SECURE_BOOT_MODE_MASK        uint32 = 0x03 << ATCA_SECURE_BOOT_MODE_SHIFT
	ATCA_SECURE_BOOT_PERSIST_EN_SHIFT uint32 = 3
	ATCA_SECURE_BOOT_PERSIST_EN_MASK  uint32 = 0x01 << ATCA_SECURE_BOOT_PERSIST_EN_SHIFT
	ATCA_SECURE_BOOT_RAND_NONCE_SHIFT uint32 = 4
	ATCA_SECURE_BOOT_RAND_NONCE_MASK  uint32 = 0x01 << ATCA_SECURE_BOOT_RAND_NONCE_SHIFT
	ATCA_SECURE_BOOT_DIGEST_SHIFT     uint32 = 8
	ATCA_SECURE_BOOT_DIGEST_MASK      uint32 = 0x0F << ATCA_SECURE_BOOT_DIGEST_SHIFT
	ATCA_SECURE_BOOT_PUB_KEY_SHIFT    uint32 = 12
	ATCA_SECURE_BOOT_PUB_KEY_MASK     uint32 = 0x0F << ATCA_SECURE_BOOT_PUB_KEY_SHIFT

	/* Chip Options */
	ATCA_CHIP_OPT_POST_EN_SHIFT     uint32 = 0
	ATCA_CHIP_OPT_POST_EN_MASK      uint32 = 0x01 << ATCA_CHIP_OPT_POST_EN_SHIFT
	ATCA_CHIP_OPT_IO_PROT_EN_SHIFT  uint32 = 1
	ATCA_CHIP_OPT_IO_PROT_EN_MASK   uint32 = 0x01 << ATCA_CHIP_OPT_IO_PROT_EN_SHIFT
	ATCA_CHIP_OPT_KDF_AES_EN_SHIFT  uint32 = 2
	ATCA_CHIP_OPT_KDF_AES_EN_MASK   uint32 = 0x01 << ATCA_CHIP_OPT_KDF_AES_EN_SHIFT
	ATCA_CHIP_OPT_ECDH_PROT_SHIFT   uint32 = 8
	ATCA_CHIP_OPT_ECDH_PROT_MASK    uint32 = 0x03 << ATCA_CHIP_OPT_ECDH_PROT_SHIFT
	ATCA_CHIP_OPT_KDF_PROT_SHIFT    uint32 = 10
	ATCA_CHIP_OPT_KDF_PROT_MASK     uint32 = 0x03 << ATCA_CHIP_OPT_KDF_PROT_SHIFT
	ATCA_CHIP_OPT_IO_PROT_KEY_SHIFT uint32 = 12
	ATCA_CHIP_OPT_IO_PROT_KEY_MASK  uint32 = 0x0F << ATCA_CHIP_OPT_IO_PROT_KEY_SHIFT

	/* Key Config */
	ATCA_KEY_CONFIG_PRIVATE_SHIFT         uint32 = 0
	ATCA_KEY_CONFIG_PRIVATE_MASK          uint32 = 0x01 << ATCA_KEY_CONFIG_PRIVATE_SHIFT
	ATCA_KEY_CONFIG_PUB_INFO_SHIFT        uint32 = 1
	ATCA_KEY_CONFIG_PUB_INFO_MASK         uint32 = 0x01 << ATCA_KEY_CONFIG_PUB_INFO_SHIFT
	ATCA_KEY_CONFIG_KEY_TYPE_SHIFT        uint32 = 2
	ATCA_KEY_CONFIG_KEY_TYPE_MASK         uint32 = 0x07 << ATCA_KEY_CONFIG_KEY_TYPE_SHIFT
	ATCA_KEY_CONFIG_LOCKABLE_SHIFT        uint32 = 5
	ATCA_KEY_CONFIG_LOCKABLE_MASK         uint32 = 0x01 << ATCA_KEY_CONFIG_LOCKABLE_SHIFT
	ATCA_KEY_CONFIG_REQ_RANDOM_SHIFT      uint32 = 6
	ATCA_KEY_CONFIG_REQ_RANDOM_MASK       uint32 = 0x01 << ATCA_KEY_CONFIG_REQ_RANDOM_SHIFT
	ATCA_KEY_CONFIG_REQ_AUTH_SHIFT        uint32 = 7
	ATCA_KEY_CONFIG_REQ_AUTH_MASK         uint32 = 0x01 << ATCA_KEY_CONFIG_REQ_AUTH_SHIFT
	ATCA_KEY_CONFIG_AUTH_KEY_SHIFT        uint32 = 8
	ATCA_KEY_CONFIG_AUTH_KEY_MASK         uint32 = 0x0F << ATCA_KEY_CONFIG_AUTH_KEY_SHIFT
	ATCA_KEY_CONFIG_PERSIST_DISABLE_SHIFT uint32 = 12
	ATCA_KEY_CONFIG_PERSIST_DISABLE_MASK  uint32 = 0x01 << ATCA_KEY_CONFIG_PERSIST_DISABLE_SHIFT
	ATCA_KEY_CONFIG_RFU_SHIFT             uint32 = 13
	ATCA_KEY_CONFIG_RFU_MASK              uint32 = 0x01 << ATCA_KEY_CONFIG_RFU_SHIFT
	ATCA_KEY_CONFIG_X509_ID_SHIFT         uint32 = 14
	ATCA_KEY_CONFIG_X509_ID_MASK          uint32 = 0x03 << ATCA_KEY_CONFIG_X509_ID_SHIFT

	/* Common Cryptographic Definitions */
	ATCA_SHA256_BLOCK_SIZE   int = 64
	ATCA_SHA256_DIGEST_SIZE  int = 32
	ATCA_AES128_BLOCK_SIZE   int = 16
	ATCA_AES128_KEY_SIZE     int = 16
	ATCA_ECCP256_KEY_SIZE    int = 32
	ATCA_ECCP256_PUBKEY_SIZE int = 64
	ATCA_ECCP256_SIG_SIZE    int = 64

	ATCA_ZONE_CONFIG uint8 = 0x00
	ATCA_ZONE_OTP    uint8 = 0x01
	ATCA_ZONE_DATA   uint8 = 0x02

	SHA_MODE_TARGET_TEMPKEY   uint8 = 0x00
	SHA_MODE_TARGET_MSGDIGBUF uint8 = 0x40
	SHA_MODE_TARGET_OUT_ONLY  uint8 = 0xC0

	/* command definitions */

	ATCA_CMD_SIZE_MIN     int   = 7
	ATCA_CMD_SIZE_MAX     int   = 4*36 + 7
	CMD_STATUS_SUCCESS    uint8 = 0x00
	CMD_STATUS_WAKEUP     uint8 = 0x11
	CMD_STATUS_BYTE_PARSE uint8 = 0x03
	CMD_STATUS_BYTE_ECC   uint8 = 0x05
	CMD_STATUS_BYTE_EXEC  uint8 = 0x0F
	CMD_STATUS_BYTE_COMM  uint8 = 0xFF

	/** \name Opcodes for Crypto Authentication device commands */
	ATCA_CHECKMAC     uint8 = 0x28 //!< CheckMac command op-code
	ATCA_DERIVE_KEY   uint8 = 0x1C //!< DeriveKey command op-code
	ATCA_INFO         uint8 = 0x30 //!< Info command op-code
	ATCA_GENDIG       uint8 = 0x15 //!< GenDig command op-code
	ATCA_GENKEY       uint8 = 0x40 //!< GenKey command op-code
	ATCA_HMAC         uint8 = 0x11 //!< HMAC command op-code
	ATCA_LOCK         uint8 = 0x17 //!< Lock command op-code
	ATCA_MAC          uint8 = 0x08 //!< MAC command op-code
	ATCA_NONCE        uint8 = 0x16 //!< Nonce command op-code
	ATCA_PAUSE        uint8 = 0x01 //!< Pause command op-code
	ATCA_PRIVWRITE    uint8 = 0x46 //!< PrivWrite command op-code
	ATCA_RANDOM       uint8 = 0x1B //!< Random command op-code
	ATCA_READ         uint8 = 0x02 //!< Read command op-code
	ATCA_SIGN         uint8 = 0x41 //!< Sign command op-code
	ATCA_UPDATE_EXTRA uint8 = 0x20 //!< UpdateExtra command op-code
	ATCA_VERIFY       uint8 = 0x45 //!< GenKey command op-code
	ATCA_WRITE        uint8 = 0x12 //!< Write command op-code
	ATCA_ECDH         uint8 = 0x43 //!< ECDH command op-code
	ATCA_COUNTER      uint8 = 0x24 //!< Counter command op-code
	ATCA_SHA          uint8 = 0x47 //!< SHA command op-code
	ATCA_AES          uint8 = 0x51 //!< AES command op-code
	ATCA_KDF          uint8 = 0x56 //!< KDF command op-code
	ATCA_SECUREBOOT   uint8 = 0x80 //!< Secure Boot command op-code
	ATCA_SELFTEST     uint8 = 0x77 //!< Self test command op-code

	/** \name Definitions of Data and Packet Sizes */
	ATCA_BLOCK_SIZE              int = 32                             //!< size of a block
	ATCA_WORD_SIZE               int = 4                              //!< size of a word
	ATCA_PUB_KEY_PAD             int = 4                              //!< size of the public key pad
	ATCA_SERIAL_NUM_SIZE         int = 9                              //!< number of bytes in the device serial number
	ATCA_RSP_SIZE_VAL            int = 7                              //!< size of response packet containing four bytes of data
	ATCA_KEY_COUNT               int = 16                             //!< number of keys
	ATCA_ECC_CONFIG_SIZE         int = 128                            //!< size of configuration zone
	ATCA_SHA_CONFIG_SIZE         int = 88                             //!< size of configuration zone
	ATCA_ECC204_CONFIG_SIZE      int = 64                             //!< size of ECC204 configuration zone
	ATCA_ECC204_CONFIG_SLOT_SIZE int = 16                             //!< size of ECC204 configuration slot size
	ATCA_OTP_SIZE                int = 64                             //!< size of OTP zone
	ATCA_DATA_SIZE               int = ATCA_KEY_COUNT * ATCA_KEY_SIZE //!< size of data zone
	ATCA_AES_GFM_SIZE            int = ATCA_BLOCK_SIZE                //!< size of GFM data

	ATCA_CHIPMODE_OFFSET           uint8 = 19   //!< ChipMode byte offset within the configuration zone
	ATCA_CHIPMODE_I2C_ADDRESS_FLAG uint8 = 0x01 //!< ChipMode I2C Address in UserExtraAdd flag
	ATCA_CHIPMODE_TTL_ENABLE_FLAG  uint8 = 0x02 //!< ChipMode TTLenable flag
	ATCA_CHIPMODE_WATCHDOG_MASK    uint8 = 0x04 //!< ChipMode watchdog duration mask
	ATCA_CHIPMODE_WATCHDOG_SHORT   uint8 = 0x00 //!< ChipMode short watchdog (~1.3s)
	ATCA_CHIPMODE_WATCHDOG_LONG    uint8 = 0x04 //!< ChipMode long watchdog (~13s)
	ATCA_CHIPMODE_CLOCK_DIV_MASK   uint8 = 0xF8 //!< ChipMode clock divider mask
	ATCA_CHIPMODE_CLOCK_DIV_M0     uint8 = 0x00 //!< ChipMode clock divider M0
	ATCA_CHIPMODE_CLOCK_DIV_M1     uint8 = 0x28 //!< ChipMode clock divider M1
	ATCA_CHIPMODE_CLOCK_DIV_M2     uint8 = 0x68 //!< ChipMode clock divider M2

	ATCA_COUNT_SIZE      int = 1                               //!< Number of bytes in the command packet Count
	ATCA_CRC_SIZE        int = 2                               //!< Number of bytes in the command packet CRC
	ATCA_PACKET_OVERHEAD     = ATCA_COUNT_SIZE + ATCA_CRC_SIZE //!< Number of bytes in the command packet

	ATCA_PUB_KEY_SIZE  int    = 64  //!< size of a p256 public key
	ATCA_PRIV_KEY_SIZE int    = 32  //!< size of a p256 private key
	ATCA_SIG_SIZE      int    = 64  //!< size of a p256 signature
	ATCA_KEY_SIZE      int    = 32  //!< size of a symmetric SHA key
	RSA2048_KEY_SIZE   uint16 = 256 //!< size of a RSA private key

	ATCA_RSP_SIZE_MIN int = 4  //!< minimum number of bytes in response
	ATCA_RSP_SIZE_4   int = 7  //!< size of response packet containing 4 bytes data
	ATCA_RSP_SIZE_72  int = 75 //!< size of response packet containing 64 bytes data
	ATCA_RSP_SIZE_64  int = 67 //!< size of response packet containing 64 bytes data
	ATCA_RSP_SIZE_32  int = 35 //!< size of response packet containing 32 bytes data
	ATCA_RSP_SIZE_16  int = 19 //!< size of response packet containing 16 bytes data
	ATCA_RSP_SIZE_MAX int = 75 //!< maximum size of response packet (GenKey and Verify command)

	OUTNONCE_SIZE uint8 = 32 //!< Size of the OutNonce response expected from several commands

	/** \name Definitions for Command Parameter Ranges
	  @{ */
	ATCA_KEY_ID_MAX    uint8 = 15 //!< maximum value for key id
	ATCA_OTP_BLOCK_MAX uint8 = 1  //!< maximum value for OTP block
	/** @} */

	/** \name Definitions for Indexes Common to All Commands
	  @{ */
	ATCA_COUNT_IDX    int = 0 //!< command packet index for count
	ATCA_OPCODE_IDX   int = 1 //!< command packet index for op-code
	ATCA_PARAM1_IDX   int = 2 //!< command packet index for first parameter
	ATCA_PARAM2_IDX   int = 3 //!< command packet index for second parameter
	ATCA_DATA_IDX     int = 5 //!< command packet index for data load
	ATCA_RSP_DATA_IDX int = 1 //!< buffer index of data in response
	/** @} */

	/** \name Definitions for Zone and Address Parameters
	  @{ */
	ATCA_ZONE_MASK           uint8  = 0x03   //!< Zone mask
	ATCA_ZONE_ENCRYPTED      uint8  = 0x40   //!< Zone bit 6 set: Write is encrypted with an unlocked data zone.
	ATCA_ZONE_READWRITE_32   uint8  = 0x80   //!< Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
	ATCA_ADDRESS_MASK_CONFIG uint16 = 0x001F //!< Address bits 5 to 7 are 0 for Configuration zone.
	ATCA_ADDRESS_MASK_OTP    uint16 = 0x000F //!< Address bits 4 to 7 are 0 for OTP zone.
	ATCA_ADDRESS_MASK        uint16 = 0x007F //!< Address bit 7 to 15 are always 0.
	ATCA_TEMPKEY_KEYID       uint16 = 0xFFFF //!< KeyID when referencing TempKey
	/** @} */

	/** \name Definitions for Key types
	  @{ */
	ATCA_B283_KEY_TYPE uint8 = 0 //!< B283 NIST ECC key
	ATCA_K283_KEY_TYPE uint8 = 1 //!< K283 NIST ECC key
	ATCA_P256_KEY_TYPE uint8 = 4 //!< P256 NIST ECC key
	ATCA_AES_KEY_TYPE  uint8 = 6 //!< AES-128 Key
	ATCA_SHA_KEY_TYPE  uint8 = 7 //!< SHA key or other data
	/** @} */

	/** \name Definitions for the AES Command
	  @{ */
	AES_MODE_IDX                  = ATCA_PARAM1_IDX  //!< AES command index for mode
	AES_KEYID_IDX                 = ATCA_PARAM2_IDX  //!< AES command index for key id
	AES_INPUT_IDX                 = ATCA_DATA_IDX    //!< AES command index for input data
	AES_COUNT               uint8 = 23               //!< AES command packet size
	AES_MODE_MASK           uint8 = 0xC7             //!< AES mode bits 3 to 5 are 0
	AES_MODE_KEY_BLOCK_MASK uint8 = 0xC0             //!< AES mode mask for key block field
	AES_MODE_OP_MASK        uint8 = 0x07             //!< AES mode operation mask
	AES_MODE_ENCRYPT        uint8 = 0x00             //!< AES mode: Encrypt
	AES_MODE_DECRYPT        uint8 = 0x01             //!< AES mode: Decrypt
	AES_MODE_GFM            uint8 = 0x03             //!< AES mode: GFM calculation
	AES_MODE_KEY_BLOCK_POS  uint8 = 6                //!< Bit shift for key block in mode
	AES_DATA_SIZE           uint8 = 16               //!< size of AES encrypt/decrypt data
	AES_RSP_SIZE                  = ATCA_RSP_SIZE_16 //!< AES command response packet size
	/** @} */

	/** \name Definitions for the CheckMac Command
	  @{ */
	CHECKMAC_MODE_IDX                     = ATCA_PARAM1_IDX   //!< CheckMAC command index for mode
	CHECKMAC_KEYID_IDX                    = ATCA_PARAM2_IDX   //!< CheckMAC command index for key identifier
	CHECKMAC_CLIENT_CHALLENGE_IDX         = ATCA_DATA_IDX     //!< CheckMAC command index for client challenge
	CHECKMAC_CLIENT_RESPONSE_IDX    uint8 = 37                //!< CheckMAC command index for client response
	CHECKMAC_DATA_IDX               uint8 = 69                //!< CheckMAC command index for other data
	CHECKMAC_COUNT                  uint8 = 84                //!< CheckMAC command packet size
	CHECKMAC_MODE_CHALLENGE         uint8 = 0x00              //!< CheckMAC mode	   0: first SHA block from key id
	CHECKMAC_MODE_BLOCK2_TEMPKEY    uint8 = 0x01              //!< CheckMAC mode bit   0: second SHA block from TempKey
	CHECKMAC_MODE_BLOCK1_TEMPKEY    uint8 = 0x02              //!< CheckMAC mode bit   1: first SHA block from TempKey
	CHECKMAC_MODE_SOURCE_FLAG_MATCH uint8 = 0x04              //!< CheckMAC mode bit   2: match TempKey.SourceFlag
	CHECKMAC_MODE_INCLUDE_OTP_64    uint8 = 0x20              //!< CheckMAC mode bit   5: include first 64 OTP bits
	CHECKMAC_MODE_MASK              uint8 = 0x27              //!< CheckMAC mode bits 3, 4, 6, and 7 are 0.
	CHECKMAC_CLIENT_CHALLENGE_SIZE  uint8 = 32                //!< CheckMAC size of client challenge
	CHECKMAC_CLIENT_RESPONSE_SIZE   uint8 = 32                //!< CheckMAC size of client response
	CHECKMAC_OTHER_DATA_SIZE        uint8 = 13                //!< CheckMAC size of "other data"
	CHECKMAC_CLIENT_COMMAND_SIZE    uint8 = 4                 //!< CheckMAC size of client command header size inside "other data"
	CHECKMAC_CMD_MATCH              uint8 = 0                 //!< CheckMAC return value when there is a match
	CHECKMAC_CMD_MISMATCH           uint8 = 1                 //!< CheckMAC return value when there is a mismatch
	CHECKMAC_RSP_SIZE                     = ATCA_RSP_SIZE_MIN //!< CheckMAC response packet size
	/** @} */

	/** \name Definitions for the Counter command
	  @{ */
	COUNTER_COUNT                 = ATCA_CMD_SIZE_MIN
	COUNTER_MODE_IDX              = ATCA_PARAM1_IDX   //!< Counter command index for mode
	COUNTER_KEYID_IDX             = ATCA_PARAM2_IDX   //!< Counter command index for key id
	COUNTER_MODE_MASK      uint8  = 0x01              //!< Counter mode bits 1 to 7 are 0
	COUNTER_MAX_VALUE      uint32 = 2097151           //!< Counter maximum value of the counter
	COUNTER_MODE_READ      uint8  = 0x00              //!< Counter command mode for reading
	COUNTER_MODE_INCREMENT uint8  = 0x01              //!< Counter command mode for incrementing
	COUNTER_RSP_SIZE              = ATCA_RSP_SIZE_4   //!< Counter command response packet size
	COUNTER_SIZE                  = ATCA_RSP_SIZE_MIN //!< Counter size in binary
	/** @} */

	/** \name Definitions for the DeriveKey Command
	  @{ */
	DERIVE_KEY_RANDOM_IDX          = ATCA_PARAM1_IDX   //!< DeriveKey command index for random bit
	DERIVE_KEY_TARGETKEY_IDX       = ATCA_PARAM2_IDX   //!< DeriveKey command index for target slot
	DERIVE_KEY_MAC_IDX             = ATCA_DATA_IDX     //!< DeriveKey command index for optional MAC
	DERIVE_KEY_COUNT_SMALL         = ATCA_CMD_SIZE_MIN //!< DeriveKey command packet size without MAC
	DERIVE_KEY_MODE          uint8 = 0x04              //!< DeriveKey command mode set to 4 as in datasheet
	DERIVE_KEY_COUNT_LARGE   uint8 = 39                //!< DeriveKey command packet size with MAC
	DERIVE_KEY_RANDOM_FLAG   uint8 = 4                 //!< DeriveKey 1. parameter; has to match TempKey.SourceFlag
	DERIVE_KEY_MAC_SIZE      uint8 = 32                //!< DeriveKey MAC size
	DERIVE_KEY_RSP_SIZE            = ATCA_RSP_SIZE_MIN //!< DeriveKey response packet size
	/** @} */

	/** \name Definitions for the ECDH Command
	  @{ */
	ECDH_PREFIX_MODE             uint8 = 0x00
	ECDH_COUNT                         = ATCA_CMD_SIZE_MIN + ATCA_PUB_KEY_SIZE
	ECDH_MODE_SOURCE_MASK        uint8 = 0x01
	ECDH_MODE_SOURCE_EEPROM_SLOT uint8 = 0x00
	ECDH_MODE_SOURCE_TEMPKEY     uint8 = 0x01
	ECDH_MODE_OUTPUT_MASK        uint8 = 0x02
	ECDH_MODE_OUTPUT_CLEAR       uint8 = 0x00
	ECDH_MODE_OUTPUT_ENC         uint8 = 0x02
	ECDH_MODE_COPY_MASK          uint8 = 0x0C
	ECDH_MODE_COPY_COMPATIBLE    uint8 = 0x00
	ECDH_MODE_COPY_EEPROM_SLOT   uint8 = 0x04
	ECDH_MODE_COPY_TEMP_KEY      uint8 = 0x08
	ECDH_MODE_COPY_OUTPUT_BUFFER uint8 = 0x0C
	ECDH_KEY_SIZE                      = ATCA_BLOCK_SIZE  //!< ECDH output data size
	ECDH_RSP_SIZE                      = ATCA_RSP_SIZE_64 //!< ECDH command packet size
	/** @} */

	/** \name Definitions for the GenDig Command
	  @{ */
	GENDIG_ZONE_IDX                = ATCA_PARAM1_IDX   //!< GenDig command index for zone
	GENDIG_KEYID_IDX               = ATCA_PARAM2_IDX   //!< GenDig command index for key id
	GENDIG_DATA_IDX                = ATCA_DATA_IDX     //!< GenDig command index for optional data
	GENDIG_COUNT                   = ATCA_CMD_SIZE_MIN //!< GenDig command packet size without "other data"
	GENDIG_ZONE_CONFIG       uint8 = 0                 //!< GenDig zone id config. Use KeyID to specify any of the four 256-bit blocks of the Configuration zone.
	GENDIG_ZONE_OTP          uint8 = 1                 //!< GenDig zone id OTP. Use KeyID to specify either the first or second 256-bit block of the OTP zone.
	GENDIG_ZONE_DATA         uint8 = 2                 //!< GenDig zone id data. Use KeyID to specify a slot in the Data zone or a transport key in the hardware array.
	GENDIG_ZONE_SHARED_NONCE uint8 = 3                 //!< GenDig zone id shared nonce. KeyID specifies the location of the input value in the message generation.
	GENDIG_ZONE_COUNTER      uint8 = 4                 //!< GenDig zone id counter. KeyID specifies the monotonic counter ID to be included in the message generation.
	GENDIG_ZONE_KEY_CONFIG   uint8 = 5                 //!< GenDig zone id key config. KeyID specifies the slot for which the configuration information is to be included in the message generation.
	GENDIG_RSP_SIZE                = ATCA_RSP_SIZE_MIN //!< GenDig command response packet size
	/** @} */

	/** \name Definitions for the GenKey Command
	  @{ */
	GENKEY_MODE_IDX                  = ATCA_PARAM1_IDX   //!< GenKey command index for mode
	GENKEY_KEYID_IDX                 = ATCA_PARAM2_IDX   //!< GenKey command index for key id
	GENKEY_DATA_IDX           uint8  = 5                 //!< GenKey command index for other data
	GENKEY_COUNT                     = ATCA_CMD_SIZE_MIN //!< GenKey command packet size without "other data"
	GENKEY_COUNT_DATA         uint16 = 10                //!< GenKey command packet size with "other data"
	GENKEY_OTHER_DATA_SIZE    uint16 = 3                 //!< GenKey size of "other data"
	GENKEY_MODE_MASK          uint8  = 0x1C              //!< GenKey mode bits 0 to 1 and 5 to 7 are 0
	GENKEY_MODE_PRIVATE       uint8  = 0x04              //!< GenKey mode: private key generation
	GENKEY_MODE_PUBLIC        uint8  = 0x00              //!< GenKey mode: public key calculation
	GENKEY_MODE_DIGEST        uint8  = 0x08              //!< GenKey mode: PubKey digest will be created after the public key is calculated
	GENKEY_MODE_PUBKEY_DIGEST uint8  = 0x10              //!< GenKey mode: Calculate PubKey digest on the public key in KeyId
	GENKEY_MODE_MAC           uint8  = 0x20              //!< Genkey mode: Calculate MAC of public key + session key
	GENKEY_PRIVATE_TO_TEMPKEY uint16 = 0xFFFF            //!< GenKey Create private key and store to tempkey (608 only)
	GENKEY_RSP_SIZE_SHORT            = ATCA_RSP_SIZE_MIN //!< GenKey response packet size in Digest mode
	GENKEY_RSP_SIZE_LONG             = ATCA_RSP_SIZE_64  //!< GenKey response packet size when returning a public key
	/** @} */

	/** \name Definitions for the HMAC Command
	  @{ */
	HMAC_MODE_IDX                   = ATCA_PARAM1_IDX   //!< HMAC command index for mode
	HMAC_KEYID_IDX                  = ATCA_PARAM2_IDX   //!< HMAC command index for key id
	HMAC_COUNT                      = ATCA_CMD_SIZE_MIN //!< HMAC command packet size
	HMAC_MODE_FLAG_TK_RAND   uint8  = 0x00              //!< HMAC mode bit 2: The value of this bit must match the value in TempKey.SourceFlag or the command will return an error.
	HMAC_MODE_FLAG_TK_NORAND uint8  = 0x04              //!< HMAC mode bit 2: The value of this bit must match the value in TempKey.SourceFlag or the command will return an error.
	HMAC_MODE_FLAG_OTP88     uint8  = 0x10              //!< HMAC mode bit 4: Include the first 88 OTP bits (OTP[0] through OTP[10]) in the message.; otherwise, the corresponding message bits are set to zero. Not applicable for ATECC508A.
	HMAC_MODE_FLAG_OTP64     uint8  = 0x20              //!< HMAC mode bit 5: Include the first 64 OTP bits (OTP[0] through OTP[7]) in the message.; otherwise, the corresponding message bits are set to zero. If Mode[4] is set, the value of this mode bit is ignored. Not applicable for ATECC508A.
	HMAC_MODE_FLAG_FULLSN    uint8  = 0x40              //!< HMAC mode bit 6: If set, include the 48 bits SN[2:3] and SN[4:7] in the message.; otherwise, the corresponding message bits are set to zero.
	HMAC_MODE_MASK           uint8  = 0x74              //!< HMAC mode bits 0, 1, 3, and 7 are 0.
	HMAC_DIGEST_SIZE         uint16 = 32                //!< HMAC size of digest response
	HMAC_RSP_SIZE                   = ATCA_RSP_SIZE_32  //!< HMAC command response packet size
	/** @} */

	/** \name Definitions for the Info Command
	  @{ */
	INFO_PARAM1_IDX                    = ATCA_PARAM1_IDX   //!< Info command index for 1. parameter
	INFO_PARAM2_IDX                    = ATCA_PARAM2_IDX   //!< Info command index for 2. parameter
	INFO_COUNT                         = ATCA_CMD_SIZE_MIN //!< Info command packet size
	INFO_MODE_REVISION                 = 0x00              //!< Info mode Revision
	INFO_MODE_KEY_VALID                = 0x01              //!< Info mode KeyValid
	INFO_MODE_STATE                    = 0x02              //!< Info mode State
	INFO_MODE_LOCK_STATUS              = 0x02              //!< Info mode Lock status for ECC204 device
	INFO_MODE_GPIO                     = 0x03              //!< Info mode GPIO
	INFO_MODE_VOL_KEY_PERMIT           = 0x04              //!< Info mode GPIO
	INFO_MODE_MAX                      = 0x03              //!< Info mode maximum value
	INFO_NO_STATE                      = 0x00              //!< Info mode is not the state mode.
	INFO_OUTPUT_STATE_MASK             = 0x01              //!< Info output state mask
	INFO_DRIVER_STATE_MASK             = 0x02              //!< Info driver state mask
	INFO_PARAM2_SET_LATCH_STATE uint16 = 0x0002            //!< Info param2 to set the persistent latch state.
	INFO_PARAM2_LATCH_SET       uint16 = 0x0001            //!< Info param2 to set the persistent latch
	INFO_PARAM2_LATCH_CLEAR     uint16 = 0x0000            //!< Info param2 to clear the persistent latch
	INFO_SIZE                   uint8  = 0x04              //!< Info return size
	INFO_RSP_SIZE                      = ATCA_RSP_SIZE_VAL //!< Info command response packet size
	/** @} */

	/** \name Definitions for the KDF Command
	  @{ */
	KDF_MODE_IDX            = ATCA_PARAM1_IDX //!< KDF command index for mode
	KDF_KEYID_IDX           = ATCA_PARAM2_IDX //!< KDF command index for key id
	KDF_DETAILS_IDX         = ATCA_DATA_IDX   //!< KDF command index for details
	KDF_DETAILS_SIZE uint16 = 4               //!< KDF details (param3) size
	KDF_MESSAGE_IDX         = uint16(ATCA_DATA_IDX) + KDF_DETAILS_SIZE

	KDF_MODE_SOURCE_MASK       uint8 = 0x03 //!< KDF mode source key mask
	KDF_MODE_SOURCE_TEMPKEY    uint8 = 0x00 //!< KDF mode source key in TempKey
	KDF_MODE_SOURCE_TEMPKEY_UP uint8 = 0x01 //!< KDF mode source key in upper TempKey
	KDF_MODE_SOURCE_SLOT       uint8 = 0x02 //!< KDF mode source key in a slot
	KDF_MODE_SOURCE_ALTKEYBUF  uint8 = 0x03 //!< KDF mode source key in alternate key buffer

	KDF_MODE_TARGET_MASK       uint8 = 0x1C //!< KDF mode target key mask
	KDF_MODE_TARGET_TEMPKEY    uint8 = 0x00 //!< KDF mode target key in TempKey
	KDF_MODE_TARGET_TEMPKEY_UP uint8 = 0x04 //!< KDF mode target key in upper TempKey
	KDF_MODE_TARGET_SLOT       uint8 = 0x08 //!< KDF mode target key in slot
	KDF_MODE_TARGET_ALTKEYBUF  uint8 = 0x0C //!< KDF mode target key in alternate key buffer
	KDF_MODE_TARGET_OUTPUT     uint8 = 0x10 //!< KDF mode target key in output buffer
	KDF_MODE_TARGET_OUTPUT_ENC uint8 = 0x14 //!< KDF mode target key encrypted in output buffer

	KDF_MODE_ALG_MASK uint8 = 0x60 //!< KDF mode algorithm mask
	KDF_MODE_ALG_PRF  uint8 = 0x00 //!< KDF mode PRF algorithm
	KDF_MODE_ALG_AES  uint8 = 0x20 //!< KDF mode AES algorithm
	KDF_MODE_ALG_HKDF uint8 = 0x40 //!< KDF mode HKDF algorithm

	KDF_DETAILS_PRF_KEY_LEN_MASK uint32 = 0x00000003 //!< KDF details for PRF, source key length mask
	KDF_DETAILS_PRF_KEY_LEN_16   uint32 = 0x00000000 //!< KDF details for PRF, source key length is 16 bytes
	KDF_DETAILS_PRF_KEY_LEN_32   uint32 = 0x00000001 //!< KDF details for PRF, source key length is 32 bytes
	KDF_DETAILS_PRF_KEY_LEN_48   uint32 = 0x00000002 //!< KDF details for PRF, source key length is 48 bytes
	KDF_DETAILS_PRF_KEY_LEN_64   uint32 = 0x00000003 //!< KDF details for PRF, source key length is 64 bytes

	KDF_DETAILS_PRF_TARGET_LEN_MASK uint32 = 0x00000100 //!< KDF details for PRF, target length mask
	KDF_DETAILS_PRF_TARGET_LEN_32   uint32 = 0x00000000 //!< KDF details for PRF, target length is 32 bytes
	KDF_DETAILS_PRF_TARGET_LEN_64   uint32 = 0x00000100 //!< KDF details for PRF, target length is 64 bytes

	KDF_DETAILS_PRF_AEAD_MASK  uint32 = 0x00000600 //!< KDF details for PRF, AEAD processing mask
	KDF_DETAILS_PRF_AEAD_MODE0 uint32 = 0x00000000 //!< KDF details for PRF, AEAD no processing
	KDF_DETAILS_PRF_AEAD_MODE1 uint32 = 0x00000200 //!< KDF details for PRF, AEAD First 32 go to target, second 32 go to output buffer

	KDF_DETAILS_AES_KEY_LOC_MASK uint32 = 0x00000003 //!< KDF details for AES, key location mask

	KDF_DETAILS_HKDF_MSG_LOC_MASK    uint32 = 0x00000003 //!< KDF details for HKDF, message location mask
	KDF_DETAILS_HKDF_MSG_LOC_SLOT    uint32 = 0x00000000 //!< KDF details for HKDF, message location in slot
	KDF_DETAILS_HKDF_MSG_LOC_TEMPKEY uint32 = 0x00000001 //!< KDF details for HKDF, message location in TempKey
	KDF_DETAILS_HKDF_MSG_LOC_INPUT   uint32 = 0x00000002 //!< KDF details for HKDF, message location in input parameter
	KDF_DETAILS_HKDF_MSG_LOC_IV      uint32 = 0x00000003 //!< KDF details for HKDF, message location is a special IV function
	KDF_DETAILS_HKDF_ZERO_KEY        uint32 = 0x00000004 //!< KDF details for HKDF, key is 32 bytes of zero
	/** @} */

	/** \name Definitions for the Lock Command
	  @{ */
	LOCK_ZONE_IDX                 = ATCA_PARAM1_IDX   //!< Lock command index for zone
	LOCK_SUMMARY_IDX              = ATCA_PARAM2_IDX   //!< Lock command index for summary
	LOCK_COUNT                    = ATCA_CMD_SIZE_MIN //!< Lock command packet size
	LOCK_ZONE_CONFIG        uint8 = 0x00              //!< Lock zone is Config
	LOCK_ZONE_DATA          uint8 = 0x01              //!< Lock zone is OTP or Data
	LOCK_ZONE_DATA_SLOT     uint8 = 0x02              //!< Lock slot of Data
	LOCK_ECC204_ZONE_DATA   uint8 = 0x00              //!< Lock ECC204 Data zone by slot
	LOCK_ECC204_ZONE_CONFIG uint8 = 0x01              //!< Lock ECC204 configuration zone by slot
	LOCK_ZONE_NO_CRC        uint8 = 0x80              //!< Lock command: Ignore summary.
	LOCK_ZONE_MASK          uint8 = 0xBF              //!< Lock parameter 1 bits 6 are 0.
	ATCA_UNLOCKED           uint8 = 0x55              //!< Value indicating an unlocked zone
	ATCA_LOCKED             uint8 = 0x00              //!< Value indicating a locked zone
	LOCK_RSP_SIZE                 = ATCA_RSP_SIZE_MIN //!< Lock command response packet size
	/** @} */

	/** \name Definitions for the MAC Command
	  @{ */
	MAC_MODE_IDX                     = ATCA_PARAM1_IDX   //!< MAC command index for mode
	MAC_KEYID_IDX                    = ATCA_PARAM2_IDX   //!< MAC command index for key id
	MAC_CHALLENGE_IDX                = ATCA_DATA_IDX     //!< MAC command index for optional challenge
	MAC_COUNT_SHORT                  = ATCA_CMD_SIZE_MIN //!< MAC command packet size without challenge
	MAC_COUNT_LONG             uint8 = 39                //!< MAC command packet size with challenge
	MAC_MODE_CHALLENGE         uint8 = 0x00              //!< MAC mode       0: first SHA block from data slot
	MAC_MODE_BLOCK2_TEMPKEY    uint8 = 0x01              //!< MAC mode bit   0: second SHA block from TempKey
	MAC_MODE_BLOCK1_TEMPKEY    uint8 = 0x02              //!< MAC mode bit   1: first SHA block from TempKey
	MAC_MODE_SOURCE_FLAG_MATCH uint8 = 0x04              //!< MAC mode bit   2: match TempKey.SourceFlag
	MAC_MODE_PTNONCE_TEMPKEY   uint8 = 0x06              //!< MAC mode bit   0: second SHA block from TempKey
	MAC_MODE_PASSTHROUGH       uint8 = 0x07              //!< MAC mode bit 0-2: pass-through mode
	MAC_MODE_INCLUDE_OTP_88    uint8 = 0x10              //!< MAC mode bit   4: include first 88 OTP bits
	MAC_MODE_INCLUDE_OTP_64    uint8 = 0x20              //!< MAC mode bit   5: include first 64 OTP bits
	MAC_MODE_INCLUDE_SN        uint8 = 0x40              //!< MAC mode bit   6: include serial number
	MAC_CHALLENGE_SIZE         uint8 = 32                //!< MAC size of challenge
	MAC_SIZE                   uint8 = 32                //!< MAC size of response
	MAC_MODE_MASK              uint8 = 0x77              //!< MAC mode bits 3 and 7 are 0.
	MAC_RSP_SIZE                     = ATCA_RSP_SIZE_32  //!< MAC command response packet size
	/** @} */

	/** \name Definitions for the Nonce Command
	  @{ */
	NONCE_MODE_IDX                   = ATCA_PARAM1_IDX        //!< Nonce command index for mode
	NONCE_PARAM2_IDX                 = ATCA_PARAM2_IDX        //!< Nonce command index for 2. parameter
	NONCE_INPUT_IDX                  = ATCA_DATA_IDX          //!< Nonce command index for input data
	NONCE_COUNT_SHORT                = ATCA_CMD_SIZE_MIN + 20 //!< Nonce command packet size for 20 bytes of NumIn
	NONCE_COUNT_LONG                 = ATCA_CMD_SIZE_MIN + 32 //!< Nonce command packet size for 32 bytes of NumIn
	NONCE_COUNT_LONG_64              = ATCA_CMD_SIZE_MIN + 64 //!< Nonce command packet size for 64 bytes of NumIn
	NONCE_MODE_MASK            uint8 = 0x03                   //!< Nonce mode bits 2 to 7 are 0.
	NONCE_MODE_SEED_UPDATE     uint8 = 0x00                   //!< Nonce mode: update seed
	NONCE_MODE_NO_SEED_UPDATE  uint8 = 0x01                   //!< Nonce mode: do not update seed
	NONCE_MODE_INVALID         uint8 = 0x02                   //!< Nonce mode 2 is invalid.
	NONCE_MODE_PASSTHROUGH     uint8 = 0x03                   //!< Nonce mode: pass-through
	NONCE_MODE_GEN_SESSION_KEY uint8 = 0x02                   //!< NOnce mode: Generate session key in ECC204 device

	NONCE_MODE_INPUT_LEN_MASK uint8 = 0x20 //!< Nonce mode: input size mask
	NONCE_MODE_INPUT_LEN_32   uint8 = 0x00 //!< Nonce mode: input size is 32 bytes
	NONCE_MODE_INPUT_LEN_64   uint8 = 0x20 //!< Nonce mode: input size is 64 bytes

	NONCE_MODE_TARGET_MASK      uint8 = 0xC0 //!< Nonce mode: target mask
	NONCE_MODE_TARGET_TEMPKEY   uint8 = 0x00 //!< Nonce mode: target is TempKey
	NONCE_MODE_TARGET_MSGDIGBUF uint8 = 0x40 //!< Nonce mode: target is Message Digest Buffer
	NONCE_MODE_TARGET_ALTKEYBUF uint8 = 0x80 //!< Nonce mode: target is Alternate Key Buffer

	NONCE_ZERO_CALC_MASK    uint16 = 0x8000 //!< Nonce zero (param2): calculation mode mask
	NONCE_ZERO_CALC_RANDOM  uint16 = 0x0000 //!< Nonce zero (param2): calculation mode random, use RNG in calculation and return RNG output
	NONCE_ZERO_CALC_TEMPKEY uint16 = 0x8000 //!< Nonce zero (param2): calculation mode TempKey, use TempKey in calculation and return new TempKey value

	NONCE_NUMIN_SIZE             uint16 = 20 //!< Nonce NumIn size for random modes
	NONCE_NUMIN_SIZE_PASSTHROUGH uint16 = 32 //!< Nonce NumIn size for 32-byte pass-through mode

	NONCE_RSP_SIZE_SHORT = ATCA_RSP_SIZE_MIN //!< Nonce command response packet size with no output
	NONCE_RSP_SIZE_LONG  = ATCA_RSP_SIZE_32  //!< Nonce command response packet size with output
	/** @} */

	/** \name Definitions for the Pause Command
	  @{ */
	PAUSE_SELECT_IDX = ATCA_PARAM1_IDX   //!< Pause command index for Selector
	PAUSE_PARAM2_IDX = ATCA_PARAM2_IDX   //!< Pause command index for 2. parameter
	PAUSE_COUNT      = ATCA_CMD_SIZE_MIN //!< Pause command packet size
	PAUSE_RSP_SIZE   = ATCA_RSP_SIZE_MIN //!< Pause command response packet size
	/** @} */

	/** \name Definitions for the PrivWrite Command
	  @{ */
	PRIVWRITE_ZONE_IDX           = ATCA_PARAM1_IDX   //!< PrivWrite command index for zone
	PRIVWRITE_KEYID_IDX          = ATCA_PARAM2_IDX   //!< PrivWrite command index for KeyID
	PRIVWRITE_VALUE_IDX    uint8 = 5                 //!< PrivWrite command index for value
	PRIVWRITE_MAC_IDX      uint8 = 41                //!< PrivWrite command index for MAC
	PRIVWRITE_COUNT        uint8 = 75                //!< PrivWrite command packet size
	PRIVWRITE_ZONE_MASK    uint8 = 0x40              //!< PrivWrite zone bits 0 to 5 and 7 are 0.
	PRIVWRITE_MODE_ENCRYPT uint8 = 0x40              //!< PrivWrite mode: encrypted
	PRIVWRITE_RSP_SIZE           = ATCA_RSP_SIZE_MIN //!< PrivWrite command response packet size
	/** @} */

	/** \name Definitions for the Random Command
	  @{ */
	RANDOM_MODE_IDX             = ATCA_PARAM1_IDX   //!< Random command index for mode
	RANDOM_PARAM2_IDX           = ATCA_PARAM2_IDX   //!< Random command index for 2. parameter
	RANDOM_COUNT                = ATCA_CMD_SIZE_MIN //!< Random command packet size
	RANDOM_SEED_UPDATE    uint8 = 0x00              //!< Random mode for automatic seed update
	RANDOM_NO_SEED_UPDATE uint8 = 0x01              //!< Random mode for no seed update
	RANDOM_NUM_SIZE       uint8 = 32                //!< Number of bytes in the data packet of a random command
	RANDOM_RSP_SIZE             = ATCA_RSP_SIZE_32  //!< Random command response packet size
	/** @} */

	/** \name Definitions for the Read Command
	  @{ */
	READ_ZONE_IDX          = ATCA_PARAM1_IDX   //!< Read command index for zone
	READ_ADDR_IDX          = ATCA_PARAM2_IDX   //!< Read command index for address
	READ_COUNT             = ATCA_CMD_SIZE_MIN //!< Read command packet size
	READ_ZONE_MASK   uint8 = 0x83              //!< Read zone bits 2 to 6 are 0.
	READ_4_RSP_SIZE        = ATCA_RSP_SIZE_VAL //!< Read command response packet size when reading 4 bytes
	READ_32_RSP_SIZE       = ATCA_RSP_SIZE_32  //!< Read command response packet size when reading 32 bytes
	/** @} */

	/** \name Definitions for the SecureBoot Command
	  @{ */
	SECUREBOOT_MODE_IDX            = ATCA_PARAM1_IDX                                                        //!< SecureBoot command index for mode
	SECUREBOOT_DIGEST_SIZE     int = 32                                                                     //!< SecureBoot digest input size
	SECUREBOOT_SIGNATURE_SIZE  int = 64                                                                     //!< SecureBoot signature input size
	SECUREBOOT_COUNT_DIG           = ATCA_CMD_SIZE_MIN + SECUREBOOT_DIGEST_SIZE                             //!< SecureBoot command packet size for just a digest
	SECUREBOOT_COUNT_DIG_SIG       = ATCA_CMD_SIZE_MIN + SECUREBOOT_DIGEST_SIZE + SECUREBOOT_SIGNATURE_SIZE //!< SecureBoot command packet size for a digest and signature
	SECUREBOOT_MAC_SIZE        int = 32                                                                     //!< SecureBoot MAC output size
	SECUREBOOT_RSP_SIZE_NO_MAC     = ATCA_RSP_SIZE_MIN                                                      //!< SecureBoot response packet size for no MAC
	SECUREBOOT_RSP_SIZE_MAC        = ATCA_PACKET_OVERHEAD + SECUREBOOT_MAC_SIZE                             //!< SecureBoot response packet size with MAC

	SECUREBOOT_MODE_MASK          uint8 = 0x07 //!< SecureBoot mode mask
	SECUREBOOT_MODE_FULL          uint8 = 0x05 //!< SecureBoot mode Full
	SECUREBOOT_MODE_FULL_STORE    uint8 = 0x06 //!< SecureBoot mode FullStore
	SECUREBOOT_MODE_FULL_COPY     uint8 = 0x07 //!< SecureBoot mode FullCopy
	SECUREBOOT_MODE_PROHIBIT_FLAG uint8 = 0x40 //!< SecureBoot mode flag to prohibit SecureBoot until next power cycle
	SECUREBOOT_MODE_ENC_MAC_FLAG  uint8 = 0x80 //!< SecureBoot mode flag for encrypted digest and returning validating MAC

	SECUREBOOTCONFIG_OFFSET         uint16 = 70     //!< SecureBootConfig byte offset into the configuration zone
	SECUREBOOTCONFIG_MODE_MASK      uint16 = 0x0003 //!< Mask for SecureBootMode field in SecureBootConfig value
	SECUREBOOTCONFIG_MODE_DISABLED  uint16 = 0x0000 //!< Disabled SecureBootMode in SecureBootConfig value
	SECUREBOOTCONFIG_MODE_FULL_BOTH uint16 = 0x0001 //!< Both digest and signature always required SecureBootMode in SecureBootConfig value
	SECUREBOOTCONFIG_MODE_FULL_SIG  uint16 = 0x0002 //!< Signature stored SecureBootMode in SecureBootConfig value
	SECUREBOOTCONFIG_MODE_FULL_DIG  uint16 = 0x0003 //!< Digest stored SecureBootMode in SecureBootConfig value
	/** @} */

	/** \name Definitions for the SelfTest Command
	  @{ */
	SELFTEST_MODE_IDX                     = ATCA_PARAM1_IDX   //!< SelfTest command index for mode
	SELFTEST_COUNT                        = ATCA_CMD_SIZE_MIN //!< SelfTest command packet size
	SELFTEST_MODE_RNG               uint8 = 0x01              //!< SelfTest mode RNG DRBG function
	SELFTEST_MODE_ECDSA_SIGN_VERIFY uint8 = 0x02              //!< SelfTest mode ECDSA verify function
	SELFTEST_MODE_ECDH              uint8 = 0x08              //!< SelfTest mode ECDH function
	SELFTEST_MODE_AES               uint8 = 0x10              //!< SelfTest mode AES encrypt function
	SELFTEST_MODE_SHA               uint8 = 0x20              //!< SelfTest mode SHA function
	SELFTEST_MODE_ALL               uint8 = 0x3B              //!< SelfTest mode all algorithms
	SELFTEST_RSP_SIZE                     = ATCA_RSP_SIZE_MIN //!< SelfTest command response packet size
	/** @} */

	/** \name Definitions for the SHA Command
	  @{ */
	SHA_COUNT_SHORT             = ATCA_CMD_SIZE_MIN
	SHA_COUNT_LONG              = ATCA_CMD_SIZE_MIN //!< Just a starting size
	ATCA_SHA_DIGEST_SIZE uint16 = 32
	SHA_DATA_MAX         uint16 = 64

	SHA_MODE_MASK              uint8 = 0x07 //!< Mask the bit 0-2
	SHA_MODE_SHA256_START      uint8 = 0x00 //!< Initialization, does not accept a message
	SHA_MODE_SHA256_UPDATE     uint8 = 0x01 //!< Add 64 bytes in the meesage to the SHA context
	SHA_MODE_SHA256_END        uint8 = 0x02 //!< Complete the calculation and return the digest
	SHA_MODE_SHA256_PUBLIC     uint8 = 0x03 //!< Add 64 byte ECC public key in the slot to the SHA context
	SHA_MODE_HMAC_START        uint8 = 0x04 //!< Initialization, HMAC calculation
	SHA_MODE_ECC204_HMAC_START uint8 = 0x03 //!< Initialization, HMAC calculation for ECC204
	SHA_MODE_HMAC_UPDATE       uint8 = 0x01 //!< Add 64 bytes in the meesage to the SHA context
	SHA_MODE_HMAC_END          uint8 = 0x05 //!< Complete the HMAC computation and return digest
	SHA_MODE_608_HMAC_END      uint8 = 0x02 //!< Complete the HMAC computation and return digest... Different command on 608
	SHA_MODE_ECC204_HMAC_END   uint8 = 0x02 //!< Complete the HMAC computation and return digest... Different mode on ECC204
	SHA_MODE_READ_CONTEXT      uint8 = 0x06 //!< Read current SHA-256 context out of the device
	SHA_MODE_WRITE_CONTEXT     uint8 = 0x07 //!< Restore a SHA-256 context into the device
	SHA_MODE_TARGET_MASK       uint8 = 0xC0 //!< Resulting digest target location mask

	SHA_RSP_SIZE       = ATCA_RSP_SIZE_32  //!< SHA command response packet size
	SHA_RSP_SIZE_SHORT = ATCA_RSP_SIZE_MIN //!< SHA command response packet size only status code
	SHA_RSP_SIZE_LONG  = ATCA_RSP_SIZE_32  //!< SHA command response packet size
	/** @} */

	/** @} */ /** \name Definitions for the Sign Command
	  @{ */
	SIGN_MODE_IDX              = ATCA_PARAM1_IDX   //!< Sign command index for mode
	SIGN_KEYID_IDX             = ATCA_PARAM2_IDX   //!< Sign command index for key id
	SIGN_COUNT                 = ATCA_CMD_SIZE_MIN //!< Sign command packet size
	SIGN_MODE_MASK             = 0xE1              //!< Sign mode bits 1 to 4 are 0
	SIGN_MODE_INTERNAL         = 0x00              //!< Sign mode	 0: internal
	SIGN_MODE_INVALIDATE       = 0x01              //!< Sign mode bit 1: Signature will be used for Verify(Invalidate)
	SIGN_MODE_INCLUDE_SN       = 0x40              //!< Sign mode bit 6: include serial number
	SIGN_MODE_EXTERNAL         = 0x80              //!< Sign mode bit 7: external
	SIGN_MODE_SOURCE_MASK      = 0x20              //!< Sign mode message source mask
	SIGN_MODE_SOURCE_TEMPKEY   = 0x00              //!< Sign mode message source is TempKey
	SIGN_MODE_SOURCE_MSGDIGBUF = 0x20              //!< Sign mode message source is the Message Digest Buffer
	SIGN_RSP_SIZE              = ATCA_RSP_SIZE_MAX //!< Sign command response packet size
	/** @} */

	/** \name Definitions for the UpdateExtra Command
	  @{ */
	UPDATE_MODE_IDX                  = ATCA_PARAM1_IDX      //!< UpdateExtra command index for mode
	UPDATE_VALUE_IDX                 = ATCA_PARAM2_IDX      //!< UpdateExtra command index for new value
	UPDATE_COUNT                     = ATCA_CMD_SIZE_MIN    //!< UpdateExtra command packet size
	UPDATE_MODE_USER_EXTRA     uint8 = 0x00                 //!< UpdateExtra mode update UserExtra (config byte 84)
	UPDATE_MODE_SELECTOR       uint8 = 0x01                 //!< UpdateExtra mode update Selector (config byte 85)
	UPDATE_MODE_USER_EXTRA_ADD       = UPDATE_MODE_SELECTOR //!< UpdateExtra mode update UserExtraAdd (config byte 85)
	UPDATE_MODE_DEC_COUNTER    uint8 = 0x02                 //!< UpdateExtra mode: decrement counter
	UPDATE_RSP_SIZE                  = ATCA_RSP_SIZE_MIN    //!< UpdateExtra command response packet size
	/** @} */

	/** \name Definitions for the Verify Command
	  @{ */
	VERIFY_MODE_IDX                      = ATCA_PARAM1_IDX   //!< Verify command index for mode
	VERIFY_KEYID_IDX                     = ATCA_PARAM2_IDX   //!< Verify command index for key id
	VERIFY_DATA_IDX               uint16 = 5                 //!< Verify command index for data
	VERIFY_256_STORED_COUNT       uint16 = 71                //!< Verify command packet size for 256-bit key in stored mode
	VERIFY_283_STORED_COUNT       uint16 = 79                //!< Verify command packet size for 283-bit key in stored mode
	VERIFY_256_VALIDATE_COUNT     uint16 = 90                //!< Verify command packet size for 256-bit key in validate mode
	VERIFY_283_VALIDATE_COUNT     uint16 = 98                //!< Verify command packet size for 283-bit key in validate mode
	VERIFY_256_EXTERNAL_COUNT     uint16 = 135               //!< Verify command packet size for 256-bit key in external mode
	VERIFY_283_EXTERNAL_COUNT     uint16 = 151               //!< Verify command packet size for 283-bit key in external mode
	VERIFY_256_KEY_SIZE           uint16 = 64                //!< Verify key size for 256-bit key
	VERIFY_283_KEY_SIZE           uint16 = 72                //!< Verify key size for 283-bit key
	VERIFY_256_SIGNATURE_SIZE     uint16 = 64                //!< Verify signature size for 256-bit key
	VERIFY_283_SIGNATURE_SIZE     uint16 = 72                //!< Verify signature size for 283-bit key
	VERIFY_OTHER_DATA_SIZE        uint16 = 19                //!< Verify size of "other data"
	VERIFY_MODE_MASK              uint8  = 0x07              //!< Verify mode bits 3 to 7 are 0
	VERIFY_MODE_STORED            uint8  = 0x00              //!< Verify mode: stored
	VERIFY_MODE_VALIDATE_EXTERNAL uint8  = 0x01              //!< Verify mode: validate external
	VERIFY_MODE_EXTERNAL          uint8  = 0x02              //!< Verify mode: external
	VERIFY_MODE_VALIDATE          uint8  = 0x03              //!< Verify mode: validate
	VERIFY_MODE_INVALIDATE        uint8  = 0x07              //!< Verify mode: invalidate
	VERIFY_MODE_SOURCE_MASK       uint8  = 0x20              //!< Verify mode message source mask
	VERIFY_MODE_SOURCE_TEMPKEY    uint8  = 0x00              //!< Verify mode message source is TempKey
	VERIFY_MODE_SOURCE_MSGDIGBUF  uint8  = 0x20              //!< Verify mode message source is the Message Digest Buffer
	VERIFY_MODE_MAC_FLAG          uint8  = 0x80              //!< Verify mode: MAC
	VERIFY_KEY_B283               uint16 = 0x0000            //!< Verify key type: B283
	VERIFY_KEY_K283               uint16 = 0x0001            //!< Verify key type: K283
	VERIFY_KEY_P256               uint16 = 0x0004            //!< Verify key type: P256
	VERIFY_RSP_SIZE                      = ATCA_RSP_SIZE_MIN //!< Verify command response packet size
	VERIFY_RSP_SIZE_MAC                  = ATCA_RSP_SIZE_32  //!< Verify command response packet size with validating MAC
	/** @} */

	/** \name Definitions for the Write Command
	  @{ */
	WRITE_ZONE_IDX             = ATCA_PARAM1_IDX   //!< Write command index for zone
	WRITE_ADDR_IDX             = ATCA_PARAM2_IDX   //!< Write command index for address
	WRITE_VALUE_IDX            = ATCA_DATA_IDX     //!< Write command index for data
	WRITE_MAC_VS_IDX    uint16 = 9                 //!< Write command index for MAC following short data
	WRITE_MAC_VL_IDX    uint16 = 37                //!< Write command index for MAC following long data
	WRITE_MAC_SIZE      uint16 = 32                //!< Write MAC size
	WRITE_ZONE_MASK     uint8  = 0xC3              //!< Write zone bits 2 to 5 are 0.
	WRITE_ZONE_WITH_MAC uint8  = 0x40              //!< Write zone bit 6: write encrypted with MAC
	WRITE_ZONE_OTP      uint8  = 1                 //!< Write zone id OTP
	WRITE_ZONE_DATA     uint8  = 2                 //!< Write zone id data
	WRITE_RSP_SIZE             = ATCA_RSP_SIZE_MIN //!< Write command response packet size
)

// go uint32 = :inin
func ATCA_COUNTER_MATCH_KEY(v uint32) uint32 {
	return ATCA_COUNTER_MATCH_KEY_MASK & (v << ATCA_COUNTER_MATCH_KEY_SHIFT)
}

//go:inline
func ATCA_CHIP_MODE_CLK_DIV(v uint32) uint32 {
	return ATCA_CHIP_MODE_CLK_DIV_MASK & (v << ATCA_CHIP_MODE_CLK_DIV_SHIFT)
}

//go:inline
func ATCA_SLOT_CONFIG_READKEY(v uint32) uint32 {
	return ATCA_SLOT_CONFIG_READKEY_MASK & (v << ATCA_SLOT_CONFIG_READKEY_SHIFT)
}

//go:inline
func ATCA_SLOT_CONFIG_WRITE_KEY(v uint32) uint32 {
	return ATCA_SLOT_CONFIG_WRITE_KEY_MASK & (v << ATCA_SLOT_CONFIG_WRITE_KEY_SHIFT)
}

//go:inline
func ATCA_SLOT_CONFIG_WRITE_CONFIG(v uint32) uint32 {
	return ATCA_SLOT_CONFIG_WRITE_CONFIG_MASK & (v << ATCA_SLOT_CONFIG_WRITE_CONFIG_SHIFT)
}

//go:inline
func ATCA_VOL_KEY_PERM_SLOT(v uint32) uint32 {
	return ATCA_VOL_KEY_PERM_SLOT_MASK & (v << ATCA_VOL_KEY_PERM_SLOT_SHIFT)
}

//go:inline
func ATCA_SECURE_BOOT_MODE(v uint32) uint32 {
	return ATCA_SECURE_BOOT_MODE_MASK & (v << ATCA_SECURE_BOOT_MODE_SHIFT)
}

//go:inline
func ATCA_SECURE_BOOT_DIGEST(v uint32) uint32 {
	return ATCA_SECURE_BOOT_DIGEST_MASK & (v << ATCA_SECURE_BOOT_DIGEST_SHIFT)
}

//go:inline
func ATCA_SECURE_BOOT_PUB_KEY(v uint32) uint32 {
	return ATCA_SECURE_BOOT_PUB_KEY_MASK & (v << ATCA_SECURE_BOOT_PUB_KEY_SHIFT)
}

//go:inline
func ATCA_SLOT_LOCKED(v uint32) uint32 {
	return (0x01 << v) & 0xFFFF
}

//go:inline
func ATCA_CHIP_OPT_ECDH_PROT(v uint32) uint32 {
	return ATCA_CHIP_OPT_ECDH_PROT_MASK & (v << ATCA_CHIP_OPT_ECDH_PROT_SHIFT)
}

//go:inline
func ATCA_CHIP_OPT_KDF_PROT(v uint32) uint32 {
	return ATCA_CHIP_OPT_KDF_PROT_MASK & (v << ATCA_CHIP_OPT_KDF_PROT_SHIFT)
}

//go:inline
func ATCA_CHIP_OPT_IO_PROT_KEY(v uint32) uint32 {
	return ATCA_CHIP_OPT_IO_PROT_KEY_MASK & (v << ATCA_CHIP_OPT_IO_PROT_KEY_SHIFT)
}

//go:inline
func ATCA_KEY_CONFIG_OFFSET(x uint32) uint32 {
	return (96 + (x)*2)
}

//go:inline
func ATCA_KEY_CONFIG_KEY_TYPE(v uint32) uint32 {
	return ATCA_KEY_CONFIG_KEY_TYPE_MASK & (v << ATCA_KEY_CONFIG_KEY_TYPE_SHIFT)
}

//go:inline
func ATCA_KEY_CONFIG_AUTH_KEY(v uint32) uint32 {
	return ATCA_KEY_CONFIG_AUTH_KEY_MASK & (v << ATCA_KEY_CONFIG_AUTH_KEY_SHIFT)
}

//go:inline
func ATCA_KEY_CONFIG_X509_ID(v uint32) uint32 {
	return ATCA_KEY_CONFIG_X509_ID_MASK & (v << ATCA_KEY_CONFIG_X509_ID_SHIFT)
}
