package mssql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/elastic/beats/v7/libbeat/common/streambuf"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/packetbeat/protos/applayer"
)

// TDS 7.4 = SQL Server 2012+
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/135d0ebe-5c4c-4a94-99bf-1811eccb9f4a

/*
MVP todo list:

Add support for all tokens received in responses
Don't need to read all of the data but we do care about the COLUMNENCRYPTION (FEATUREEXTACK)

1) bug:
// When calling from SSMS we need to process CEKTable in the ColumnMeta
// When called from Go test harness we don't have a CEKTable
// Either because an older version of TDS is being used (not sure how we check this) or there is no CEK table.
// Revisit and figure this out


1) Token support:
** Error: Unsupported token: featureExtackToken 0xae
** Error: Not Implemented: returnStatusToken 0x79
** Error: Ignoring message
-- Bug when processing RPC message during logon:
** ProcName:
	ۧँ퀄㐀ĆSELECT
	dtb.collation_name AS [Collation],
	dtb.name AS [DatabaseName2]
	FROM
	master.sys.databases AS dtb
	WHERE
	(dtb.name=@_msparam_0) 㓧ऀ퀄㐀4@_msparam_0 nvarchar(4000)䀋开洀猀瀀愀爀愀洀开　 䃧ट퀄㐀
																						master

2) Finish off adding support for all datatypes

3) Add RPC support (will need test app)

4) Add a readme:
- Todo list
- Messages with specific SQL fields:
-- SQL Batch (tokenless stream)
-- RPC (token stream)
-- Bulk Load (token stream) - support?
-- Both types return a Tabular Result (token stream)


Bugs:
** Error: Not Implemented: sessionStateToken 0xe4 (hmmm - is this off the back of sql batch or rpc call?)
** Error: Not Implemented: orderToken 0xa9
** Error: Not Implemented: RPC message 0x3
** Error: Ignoring message
** Sort out how to handle empty(ish) buffers

- Probably don't need it but add in header validation to ensure we don't get differing batch types
- Add the ECS fields into pub.go/trans.go
- Validate the header details match between separate packets
- Add support for RPC calls
- Add tests
*/

type messageHeader struct {
	messageType byte
	status      byte
	// length	int (bytes 3&4)
	// spid 	(bytes 5&6)
	// packetId	(byte 7)
}

type parser struct {

	// todo: We pass in and set this based on the connection trans in mssql.go. Find a better way to be aware of previous request type
	originatingRequestType string

	buf       streambuf.Buffer
	config    *parserConfig
	message   *message
	onMessage func(m *message) error
	header    *messageHeader
}

type parserConfig struct {
	maxBytes int
}

// It doesn't represent an individual packet that's being processed but a complete message request or response
type message struct {
	// Set these variables based on the first request that we get
	applayer.Message

	isComplete bool

	// Wrap these up in different types once we start parsing more request types
	messageType  string
	colDataTypes []byte
	rowsReturned int
	resultSets   int
	sqlBatch     string
}

// Error code if stream exceeds max allowed size on append.
var (
	ErrStreamTooLarge = errors.New("Stream data too large")
)

func (p *parser) init(
	cfg *parserConfig,
	onMessage func(*message) error,
) {
	*p = parser{
		buf:       streambuf.Buffer{},
		config:    cfg,
		onMessage: onMessage,
	}
}

func (p *parser) append(data []byte) error {

	// Once validated then append data portion of the packet to the buffer to buffer
	if _, err := p.buf.Write(data[8:]); err != nil {
		return err
	}

	if p.config.maxBytes > 0 && p.buf.Total() > p.config.maxBytes {
		return ErrStreamTooLarge
	}
	return nil
}

// Look at a better way to pass connection & transaction level data about
func (p *parser) feed(ts time.Time, data []byte, originatingRequestType string, columnEncryption *bool) error {

	if len(data) < 8 {
		// todo: not sure if empty buffer should be an error
		return fmt.Errorf("Empty(ish) buffer. Length: %d", len(data))
	}

	// We need to parse the header at this point and only append the data
	header, err := parseHeader(data)
	if err != nil {
		return err
	}

	// Validate the header - check that the header we now have reflects what we were previously processing (if we were already processing)

	if p.message == nil {
		// allocate new message object to be used by parser with current timestamp
		p.message = p.newMessage(ts)
	}

	// Need to set to the latest header in case we have now completed:
	p.header = header

	// This will append the data portion of the packet
	if err := p.append(data); err != nil {
		return err
	}

	// Not sure if this should be an error?
	if ignoreMessage(p.header) {
		//return fmt.Errorf("Ignoring message")
		return nil
	}

	// Wait for more data if incomplete
	if !isComplete(p.header) {
		return nil
	}

	// todo: Find a more elgant way to do this instead of passing around the originating request type as a string
	p.originatingRequestType = originatingRequestType

	// todo: Effectively we only call into this once for a complete message even if it is made up of various packets
	// newMessage creates an appPlayer message containing all of our core fields. Do we need to care about merging messages
	// together as we need to capture 'core' information from various packets. Currently we will take the 'core' fields
	// from the last packet as we only process on completion of a message so this feels wrong

	// Todo: dont' just pass down columnEncryption like this
	if err := p.parse(columnEncryption); err != nil {

		logp.Info("\n** Error: Complete buffer: % x\n", p.buf.BufferedBytes())

		data := make([]byte, p.buf.Len())
		p.buf.Read(data)
		if len(data) > 500 {
			logp.Info("\n** Error: Remaining data in buffer: % x\n   Header: %v", data[:500], p.header)
		} else {
			logp.Info("\n** Error: Remaining data in buffer: % x\n   Header: %v", data, p.header)
		}
		return err
	}

	if err := p.onMessage(p.message); err != nil {
		// Do we need to reset if we error?
		p.buf.Reset()
		p.header = &messageHeader{}
		p.message = nil
		return err
	}

	// Reset parser
	p.buf.Reset()
	p.header = &messageHeader{}
	p.message = nil

	return nil
}

func (p *parser) newMessage(ts time.Time) *message {
	logp.Info("parser.newMessage()")
	return &message{
		Message: applayer.Message{
			Ts: ts,
		},
	}
}

func (p *parser) parse(columnEncryption *bool) error {

	switch p.header.messageType {
	case sqlBatchMessage:
		p.message.messageType = "SQLBatch"
		p.message.IsRequest = true

		// Skip over the header (header length - the 4 Bytes that we have just read)
		headerLen, err := p.readUInt32(littleEndian)
		if err != nil {
			return err
		}
		p.buf.Advance(int(headerLen) - 4)

		// Read the rest of the packet data
		p.message.sqlBatch, err = p.readUCS2String(p.buf.Len())
		if err != nil {
			return err
		}

		logp.Info("** sqlbatch: %s", p.message.sqlBatch)

	case preTds7LoginMessage:
		p.message.messageType = "Pre-TDS7 Login"
		p.message.IsRequest = true
		p.buf.Advance(p.buf.Len())
	case rpcMessage:
		// Can't recreate this from SSMS so will need to write a proggie to exercise RPC
		p.message.messageType = "RPC"
		p.message.IsRequest = true

		// Skip over the header (header length - the 4 Bytes that we have just read)
		headerLen, err := p.readUInt32(littleEndian)
		if err != nil {
			return err
		}
		p.buf.Advance(int(headerLen) - 4)

		// Read the name of the proc
		nameLen, err := p.readUInt16(littleEndian)
		if err != nil {
			return err
		}
		procName, err := p.readUCS2String(int(nameLen))
		if err != nil {
			return err
		}
		logp.Info("** ProcName: %s", procName)

		// Print out the rest of the proc stream
		data := make([]byte, p.buf.Len())
		p.buf.Read(data)

		/*
			RPCRequest = ALL_HEADERS
			RPCReqBatch
			*((BatchFlag / NoExecFlag) RPCReqBatch)
		*/

		/*
			ProcID = USHORT
			ProcIDSwitch = %xFF %xFF
			ProcName = US_VARCHAR (16bit unsigned int length)
			NameLenProcID = ProcName
		*/

	case tabularResultMessage:

		p.message.messageType = "Tabular result"
		p.message.IsRequest = false

		/*
			todo: Find a better way to coordinate the request / response. Don't use the string on the transaction
			There are tabular results that we want to dismiss:
			Many request types produce tabular results. We don't care abour reading the data of a lot of them
		*/
		// if !(p.originatingRequestType == "SQLBatch" || p.originatingRequestType == "RPC" || p.originatingRequestType == "Login ") || p.originatingRequestType == "" {
		// The below are specifically tokenless streams that I don't think we care about
		if p.originatingRequestType == "Pre-Login" || p.originatingRequestType == "Attention Signal" {
			p.buf.Advance(p.buf.Len())
			break
		}

		if err := parseTokenStream(p, columnEncryption); err != nil {
			return err
		}

	case attentionSignalMessage:
		p.message.messageType = "Attention Signal"
		p.message.IsRequest = true
		p.buf.Advance(p.buf.Len())
	case bulkLoadDataMessage:
		p.message.messageType = "Bulk load data"
		p.message.IsRequest = true
		p.buf.Advance(p.buf.Len())
	case federatedAuthenticationTokenMesage:
		p.message.messageType = "Federated Authentication Token"
		p.message.IsRequest = true
		p.buf.Advance(p.buf.Len())
	case transactionManagerRequestMessage:
		p.message.messageType = "Transaction Manager Request"
		p.message.IsRequest = true
		p.buf.Advance(p.buf.Len())
	case tds7LoginMessage:
		p.message.messageType = "TDS7 Login"
		p.message.IsRequest = true

		/*
			LOGIN7 =
				Length			= DWORD
				TDSVersion		= DWORD
				PacketSize		= DWORD
				ClientProgVer	= DWORD
				ClientPID		= DWORD
				ConnectionID	= DWORD
				OptionFlags1	= BYTE
				OptionFlags2	= BYTE
				TypeFlags (FRESERVEDBYTE / OptionFlags3) = BYTE
				ClientTimeZone	= LONG
				ClientLCID		= 4 BYTES
				OffsetLength	= 26x USHORT + 6BYTE + DWORD
				Data
				[FeatureExt]
		*/

		p.buf.Advance(p.buf.Len())
	case sspiMessage:
		p.message.messageType = "SSPI"
		p.message.IsRequest = true
		p.buf.Advance(p.buf.Len())
	case preLoginMessage:
		p.message.messageType = "Pre-Login"
		p.message.IsRequest = true
		p.buf.Advance(p.buf.Len())
	default:
		return fmt.Errorf("Unrecognised message type: 0x%x", p.header.messageType)
	}

	logp.Info("Finished reading 0x%x packet. Remaining data: %d bytes", p.header.messageType, p.buf.Len())

	return nil
}

func parseTokenStream(p *parser, columnEncryption *bool) error {
	// The below is effectively our parseTokenStream function:
	for p.buf.Len() > 0 {
		// We need to loop around the below and pull off each token as we go
		tokenType, err := p.buf.ReadByte()
		if err != nil {
			return err
		}

		switch tokenType {
		case colMetadataToken:
			columnCount, err := p.readUInt16(littleEndian)
			if err != nil {
				return err
			}

			// If the client supports column encryption then skip over the CEK table
			// We are only supporting the fact that COLUMNENCRYPTION has been negotiated. Not the presence of any encryption keys
			if *columnEncryption == true {
				p.buf.Advance(2)
			}

			if p.message.colDataTypes, err = parseColumnMetadata(p, int(columnCount)); err != nil {
				return err
			}
		case colInfoToken:
			return fmt.Errorf("Not Implemented: colInfoToken 0x%x", tokenType)
		case dataClassificationToken:
			return fmt.Errorf("Not Implemented: dataClassificationToken 0x%x", tokenType)
		case doneToken:
			// todo: Revisit this - can we pull our row count for the current dataset from here?
			/*
				This token is used to indicate the completion of a SQL statement.
				As multiple SQL statements can be sent to the server in a single SQL batch, multiple DONE tokens can
				be generated. In this case, all but the final DONE token will have a Status value with DONE_MORE bit set (details follow).

				Status = USHORT
				CurCmd = USHORT
				DoneRowCount = LONG / ULONGLONG;
				(Changed to ULONGLONG in TDS 7.2)

				DONE =	TokenType
						Status
						CurCmd
						DoneRowCount
			*/

			// todo: we should really read the row count from here:
			// For the moment just ignore the 12 bytes
			p.buf.Advance(12)
			p.message.resultSets++

			//p.buf.Advance(p.buf.Len())
		case doneProcToken:
			p.buf.Advance(12)
		case doneInProcToken:
			p.buf.Advance(12)
		case envChangeToken:
			// todo: move these into an advance varlen 16
			streamLen, err := p.readUInt16(littleEndian)
			if err != nil {
				return err
			}
			if err := p.buf.Advance(int(streamLen)); err != nil {
				return err
			}
		case errorToken:
			streamLen, err := p.readUInt16(littleEndian)
			if err != nil {
				return err
			}
			if err := p.buf.Advance(int(streamLen)); err != nil {
				return err
			}
		case featureExtackToken:

			for {
				f, err := p.buf.ReadByte()
				if err != nil {
					return err
				}
				if f == 0xff {
					break
				}
				if f == 0x04 {
					*columnEncryption = true
				}
				// Now just advance the buffer
				ackDataLen, err := p.readUInt32(littleEndian)
				if err != nil {
					return err
				}
				if err := p.buf.Advance(int(ackDataLen)); err != nil {
					return err
				}
			}

			return fmt.Errorf("Unsupported token: featureExtackToken 0x%x", tokenType)
		case infoToken:
			streamLen, err := p.readUInt16(littleEndian)
			if err != nil {
				return err
			}
			if err := p.buf.Advance(int(streamLen)); err != nil {
				return err
			}
		case loginAckToken:
			streamLen, err := p.readUInt16(littleEndian)
			if err != nil {
				return err
			}
			if err := p.buf.Advance(int(streamLen)); err != nil {
				return err
			}
		case nbcRowToken:
			/*
				MS-TDS Spec - Page 106:
				NBCROW, introduced in TDS 7.3.B, is used to send a row as defined by the COLMETADATA token to the client
				with null bitmap compression. Null bitmap compression is implemented by using a single bit to specify
				whether the column is null or not null and also by removing all null column values from the row.
				Removing the null column values (which can be up to 8 bytes per null instance) from the row provides
				the compression. The null bitmap contains one bit for each column defined in COLMETADATA.
				In the null bitmap, a bit value of 1 means that the column is null and therefore not present in the row,
				and a bit value of 0 means that the column is not null and is present in the row.
				The null bitmap is always rounded up to the nearest multiple of 8 bits, so there might be 1 to 7 leftover
				reserved bits at the end of the null bitmap in the last byte of the null bitmap. NBCROW is only used by
				TDS result set streams from server to client. NBCROW MUST NOT be used in BulkLoadBCP streams.
				NBCROW MUST NOT be used in TVP row streams.
			*/

			// Up the row count
			p.message.rowsReturned++

			nbcLength := len(p.message.colDataTypes) / 8
			if len(p.message.colDataTypes)%8 != 0 {
				nbcLength++
			}

			nbc := make([]byte, nbcLength)
			if _, err := p.buf.Read(nbc); err != nil {
				return err
			}

			for i := 0; i < len(p.message.colDataTypes); i++ {
				// Logic based on: https://play.golang.org/p/copjZW4Pl8_r
				nbcIdx := i / 8
				if nbc[nbcIdx]&1 == 1 {
					nbc[nbcIdx] = nbc[nbcIdx] >> 1
					continue
				}
				nbc[nbcIdx] = nbc[nbcIdx] >> 1
				if err := advanceBufferForDataType(p, p.message.colDataTypes[i]); err != nil {
					return err
				}
			}
		case orderToken:
			streamLen, err := p.readUInt16(littleEndian)
			if err != nil {
				return err
			}
			if err := p.buf.Advance(int(streamLen)); err != nil {
				return err
			}
		case returnStatusToken:
			if err := p.buf.Advance(4); err != nil {
				return err
			}
		case returnValueToken:
			return fmt.Errorf("Not Implemented: returnValueToken 0x%x", tokenType)
		case rowToken:
			p.message.rowsReturned++

			for i := 0; i < len(p.message.colDataTypes); i++ {
				if err := advanceBufferForDataType(p, p.message.colDataTypes[i]); err != nil {
					return err
				}
			}
		case sessionStateToken:
			streamLen, err := p.readUInt32(littleEndian)
			if err != nil {
				return err
			}
			if err := p.buf.Advance(int(streamLen)); err != nil {
				return err
			}
		case sspiToken:
			streamLen, err := p.readUInt16(littleEndian)
			if err != nil {
				return err
			}
			if err := p.buf.Advance(int(streamLen)); err != nil {
				return err
			}
		case tabNameToken:
			return fmt.Errorf("Not Implemented: tabnameToken 0x%x", tokenType)

		// ** Unsupported token types
		// Deprecated in TDS 7.4:
		case altMetadataToken:
			return fmt.Errorf("Unsupported: altMetadataToken 0x%x", tokenType)
		case altRowToken:
			return fmt.Errorf("Not Implemented: altRowToken 0x%x", tokenType)
		// Token removed in TDS 7.2:
		case offsetToken:
			return fmt.Errorf("Unsupported token: offsetToken 0x%x", tokenType)
		case fedAuthInfoToken:
			return fmt.Errorf("Unsupported token: fedAuthInfoToken 0x%x", tokenType)
		default:
			return fmt.Errorf("Unrecognised Token: 0x%x", tokenType)
		}
	}
	return nil
}

func parseColumnMetadata(p *parser, columnCount int) (colType []byte, err error) {

	/* 2.2.7.4 - COLMETADATA token
	   Notes:

		COLMETADATA =
		- TokenType
		- Count
		- [CekTable] -->>
			Set based on COLUMNENCRYPTION. Specified in the login7 stream and a FEATUREEXTACK message
			As we only deal with messages at a packet level we won't have this information
			For the moment we will have to fail inelegantly - need to test
		- NoMetaData / (1*ColumnData) -->> todo: NoMetaData. Count will be 0xFFFF

		ColumnData =
		- UserType (4 bytes)
		- Flags (2 bytes)
		- TYPE_INFO
		- [TableName]
		- [CryptoMetaData]
		- ColName

	   - The TableName element is specified only if a text, ntext, or image column is included in the result set.

	*/

	/*
		todo:
		// variable length data types:
		decimaltype         = 0x37
		numerictype         = 0x3f
		decimalntype        = 0x6a
		numericntype        = 0x6c
		datetime2ntype      = 0x2a
		datetimeoffsetntype = 0x2b
		chartype            = 0x2f
		binarytype          = 0x2d
		varbinarytype       = 0x25
		bigvarbinarytype    = 0xa5
		bigbinarytype       = 0xad
		bigchartype         = 0xaf
		xmltype             = 0xf1
		udttype             = 0xf0
		texttype            = 0x23
		imagetype           = 0x22
		ntexttype           = 0x63
		ssvarianttype       = 0x62
	*/

	colType = make([]byte, columnCount)

	for i := 0; i < columnCount; i++ {

		// Skip usertype (4 bytes) & flags (2 bytes)
		// Validate that the column is not encrypted (See 2.2.5.7 for EK Rule definitions). Fail if it is
		p.buf.Advance(6)

		colType[i], err = p.buf.ReadByte()
		if err != nil {
			return
		}

		// See: 2.2.5.6 Type Info Rule Definition
		// Note (DATE MUST NOT have a TYPE_VARLEN. The value is either 3 bytes or 0 bytes (null).)
		switch colType[i] {
		case
			bittype, int1type, int2type, int4type, int8type,
			datetim4type, datetimetype, datentype,
			money4type, moneytype,
			flt4type, flt8type,
			nulltype:

			if _, err = readColumnName(p); err != nil {
				return
			}

		case intntype, bitntype, datetimntype, fltntype, moneyntype, guidtype, timentype:
			// 1-byte length
			if err = p.buf.Advance(1); err != nil {
				return colType, err
			}
			if _, err = readColumnName(p); err != nil {
				return
			}

		case ssvarianttype:
			// 4-byte info
			if err = p.buf.Advance(4); err != nil {
				return colType, err
			}
			if _, err = readColumnName(p); err != nil {
				return
			}

		case bigvarchartype, nvarchartype:
			// 5-byte collation (2.2.5.1.2), followed by 2-byte max length
			if err = p.buf.Advance(7); err != nil {
				return colType, err
			}
			if _, err = readColumnName(p); err != nil {
				return
			}

		default:
			return colType, fmt.Errorf("Parse Metadata. Unhandled data type: x%x", colType[i])
		}
	}

	return colType, nil
}

func parseHeader(data []byte) (header *messageHeader, err error) {
	logp.Info("** Parsing header: % x", data[:8])
	header = &messageHeader{
		messageType: data[0],
		status:      data[1],
	}
	return
}

func ignoreMessage(header *messageHeader) bool {
	return header.status&ignoreStatus == ignoreStatus && header.status&eomStatus == eomStatus
}

func isComplete(header *messageHeader) bool {
	return header.status&eomStatus == eomStatus
}

func advanceBufferForDataType(p *parser, dataType byte) error {
	switch dataType {
	/*
		todo:
		// fixed length data types:
		nulltype     = 0x1f

		// variable length data types:
		decimaltype         = 0x37
		numerictype         = 0x3f
		decimalntype        = 0x6a
		numericntype        = 0x6c
		datetime2ntype      = 0x2a
		datetimeoffsetntype = 0x2b
		chartype            = 0x2f
		binarytype          = 0x2d
		varbinarytype       = 0x25
		bigvarbinarytype    = 0xa5
		bigbinarytype       = 0xad
		bigchartype         = 0xaf
		xmltype             = 0xf1
		udttype             = 0xf0
		texttype            = 0x23
		imagetype           = 0x22
		ntexttype           = 0x63
		ssvarianttype       = 0x62
	*/
	case int1type, bittype:
		p.buf.Advance(1)
	case int2type:
		p.buf.Advance(2)
	case int4type, datetim4type, flt4type, money4type:
		p.buf.Advance(4)
	case int8type, moneytype, datetimetype, flt8type:
		p.buf.Advance(8)
	case intntype, bitntype, datetimntype, fltntype, moneyntype, guidtype, datentype, timentype:
		// Variable length - specified by first byte
		len, err := p.buf.ReadByte()
		if err != nil {
			return err
		}
		p.buf.Advance(int(len))
	case varchartype, bigvarchartype, nvarchartype, nchartype:
		charCount, err := p.readUInt16(littleEndian)
		if err != nil {
			return err
		}
		if err := p.buf.Advance(int(charCount)); err != nil {
			return err
		}
	case ssvarianttype:
		charCount, err := p.readUInt32(littleEndian)
		if err != nil {
			return err
		}
		if err := p.buf.Advance(int(charCount)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("Advance buffer. Unhandled data type 0x%x", dataType)
	}
	return nil
}

func readColumnName(p *parser) (columnName string, err error) {
	colNameLen, err := p.buf.ReadByte()
	if err != nil {
		return
	}

	return p.readUCS2String(int(colNameLen) * 2)
}

const (
	littleEndian = 0
	bigEndian    = 1
)

func (p *parser) readUInt16(endianness int) (v uint16, err error) {
	b := make([]byte, 2)
	if _, err = p.buf.Read(b); err != nil {
		return
	}

	if endianness == littleEndian {
		v = binary.LittleEndian.Uint16(b)
	} else {
		v = binary.BigEndian.Uint16(b)
	}
	return
}

func (p *parser) readUInt32(endianness int) (v uint32, err error) {
	b := make([]byte, 4)
	if _, err = p.buf.Read(b); err != nil {
		return
	}

	if endianness == littleEndian {
		v = binary.LittleEndian.Uint32(b)
	} else {
		v = binary.BigEndian.Uint32(b)
	}
	return
}

// The usage of utf-16 for decoding is similar to the following go sql database driver:
// https://github.com/denisenkom/go-mssqldb/blob/06a60b6afbbc676d19209e339b20f8b685e7da34/tds.go#L419
func (p *parser) readUCS2String(length int) (s string, err error) {
	b := make([]byte, length)
	if _, err = p.buf.Read(b); err != nil {
		return
	}
	reader := bytes.NewReader(b)
	uChars := make([]uint16, len(b)/2)
	binary.Read(reader, binary.LittleEndian, uChars)
	s = string(utf16.Decode(uChars))
	return
}
