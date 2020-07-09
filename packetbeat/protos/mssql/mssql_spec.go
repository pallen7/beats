package mssql

// token types
const (
	altMetadataToken        = 0x88 // (variable count)
	altRowToken             = 0xd3 // (zero length)
	colMetadataToken        = 0x81 // (variable count)
	colInfoToken            = 0xa5 // (variable length)
	dataClassificationToken = 0xa3 // (variable length) (introduced in tds 7.4)
	doneToken               = 0xfd // (fixed length)
	doneProcToken           = 0xfe // (fixed length)
	doneInProcToken         = 0xff // (fixed length)
	envChangeToken          = 0xe3 // (variable length)
	errorToken              = 0xaa // (variable length)
	featureExtackToken      = 0xae // (variable length) ; (introduced in tds 7.4)
	fedAuthInfoToken        = 0xee // (variable length) ; (introduced in tds 7.4)
	infoToken               = 0xab // (variable length)
	loginAckToken           = 0xad // (variable length)
	nbcRowToken             = 0xd2 // (zero length); (introduced in tds 7.3)
	offsetToken             = 0x78 // (fixed length)
	orderToken              = 0xa9 // (variable length)
	returnStatusToken       = 0x79 // (fixed length)
	returnValueToken        = 0xac // (variable length)
	rowToken                = 0xd1 // (zero length)
	sessionStateToken       = 0xe4 // (variable length) ; (introduced in tds 7.4)
	sspiToken               = 0xed // (variable length)
	tabNameToken            = 0xa4 // (variable length)
)

const (
	// fixed length data types:
	nulltype     = 0x1f
	int1type     = 0x30
	bittype      = 0x32
	int2type     = 0x34
	int4type     = 0x38
	datetim4type = 0x3a
	flt4type     = 0x3b
	moneytype    = 0x3c
	datetimetype = 0x3d
	flt8type     = 0x3e
	money4type   = 0x7a
	int8type     = 0x7f

	// variable length data types:
	guidtype            = 0x24
	intntype            = 0x26
	decimaltype         = 0x37
	numerictype         = 0x3f
	bitntype            = 0x68
	decimalntype        = 0x6a
	numericntype        = 0x6c
	fltntype            = 0x6d
	moneyntype          = 0x6e
	datetimntype        = 0x6f
	datentype           = 0x28
	timentype           = 0x29
	datetime2ntype      = 0x2a
	datetimeoffsetntype = 0x2b
	chartype            = 0x2f
	varchartype         = 0x27
	binarytype          = 0x2d
	varbinarytype       = 0x25
	bigvarbinarytype    = 0xa5
	bigvarchartype      = 0xa7
	bigbinarytype       = 0xad
	bigchartype         = 0xaf
	nvarchartype        = 0xe7
	nchartype           = 0xef
	xmltype             = 0xf1
	udttype             = 0xf0
	texttype            = 0x23
	imagetype           = 0x22
	ntexttype           = 0x63
	ssvarianttype       = 0x62
)

const (
	normalStatus                  = 0x00
	eomStatus                     = 0x01
	ignoreStatus                  = 0x02 // (0x01 MUST also be set)
	resetConnectionStatus         = 0x08
	resetConnectionStatusSkipTran = 0x08
)

const (
	sqlBatchMessage                    = 0x01
	preTds7LoginMessage                = 0x02
	rpcMessage                         = 0x03
	tabularResultMessage               = 0x04
	attentionSignalMessage             = 0x06
	bulkLoadDataMessage                = 0x07
	federatedAuthenticationTokenMesage = 0x08
	transactionManagerRequestMessage   = 0x0e
	tds7LoginMessage                   = 0x10
	sspiMessage                        = 0x11
	preLoginMessage                    = 0x12
)
