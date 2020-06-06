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

/*
todo:
- Keep the publisher to publish events but remove trans.go. We will manage the transaction within the parser.
- We don't need a message structure as we will be updating the request/response object that sites on
  the parser as we receive messages
- Once we have a complete transaction (request & response) we want to call into pub.onTransaction to create the event
*/

type mssqlRequest struct {
	requestType string
}

type mssqlResponse struct {
	responseType string
	colDataTypes []byte
	rowsReturned int
}

type parser struct {
	buf     streambuf.Buffer
	config  *parserConfig
	message *message

	// Currently these 2 are mutually exclusive. If we remove trans.go can we just manage this ourselves?
	request  *mssqlRequest
	response *mssqlResponse

	// Rename this and the corresponding function in trans.go to onCompleteMessage
	// We handle the 'merging' of packets into a complete message in the parser to no need for all of the correlation logic
	onMessage func(m *message) error
}

type parserConfig struct {
	maxBytes int
}

// Do we even need this as we are
type message struct {
	applayer.Message

	// indicator for parsed message being complete or requires more messages
	// (if false) to be merged to generate full message.
	isComplete bool

	// list element use by 'transactions' for correlation
	next *message

	// We probably want to differentiate these types from the 'working' types held at the parser level
	request  *mssqlRequest
	response *mssqlResponse
}

// Error code if stream exceeds max allowed size on append.
var (
	ErrStreamTooLarge = errors.New("Stream data too large")
)

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
	_, err := p.buf.Write(data)
	if err != nil {
		return err
	}

	if p.config.maxBytes > 0 && p.buf.Total() > p.config.maxBytes {
		return ErrStreamTooLarge
	}
	return nil
}

func (p *parser) feed(ts time.Time, data []byte) error {
	if err := p.append(data); err != nil {
		return err
	}

	// todo: Effectively we only call into this once for a complete message even if it is made up of various packets
	// newMessage creates an appPlayer message containing all of our core fields. Do we need to care about merging messages
	// together as we need to capture 'core' information from various packets. Currently we will take the 'core' fields
	// from the last packet as we only process on completion of a message so this feels wrong
	for p.buf.Total() > 0 {
		if p.message == nil {
			// allocate new message object to be used by parser with current timestamp
			p.message = p.newMessage(ts)
		}

		msg, err := p.parse()
		if err != nil {
			logp.Info("** parse returned error: %s", err)

			// Read the rest of the buffer data - no need to check for errors
			data := make([]byte, p.buf.Len())
			p.buf.Read(data)
			logp.Info("** remaining data in buffer: %v", data)

			return err
		}
		if msg == nil {
			logp.Info("** parse returned nil msg")
			break // wait for more data
		}

		// reset buffer and message -> handle next message in buffer
		// If we aren't at the end of the message does this actually reset?
		p.buf.Reset()
		p.message = nil

		// call message handler callback
		// We don't really care about saving every packet - rename the below to onCompleteMessage
		// We can remove the logic in trans.onMessage that tries to take care of the correlation
		if msg.isComplete {
			if err := p.onMessage(msg); err != nil {
				return err
			}
		}
	}

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

func (p *parser) parse() (*message, error) {
	/* 2.2.3.1 Packet Header

	// Byte	Usage
	// 1	Type
	// 2	Status
	// 3,4	Length
	// 5,6	SPID
	// 7	PacketId
	// 8	Unused

	// 2nd byte is a bit field - see if this is the end of the message
	/* Spec:
	0x00 "Normal" message.
	0x01 End of message (EOM). The packet is the last packet in the whole request
	0x02 (From client to server) Ignore this event (0x01 MUST also be set).
	0x08 RESETCONNECTION
		(Introduced in TDS 7.1)
		(From client to server) Reset this connection before processing event. Only set for event types Batch,
		RPC, or Transaction Manager request. If clients want to set this bit, it MUST be part of the first packet of
		the message. This signals the server to clean up the environment state of the connection back to the
		default environment setting, effectively simulating a logout and a subsequent login, and provides server
		support for connection pooling. This bit SHOULD be ignored if it is set in a packet that is not the first
		packet of the message.
		This status bit MUST NOT be set in conjunction with the RESETCONNECTIONSKIPTRAN bit. Distributed
		transactions and isolation levels will not be reset.
	0x10 RESETCONNECTIONSKIPTRAN
		(Introduced in TDS 7.3)
		(From client to server) Reset the connection before processing event but do not modify the transaction
		state (the state will remain the same before and after the reset). The transaction in the session can be a
		local transaction that is started from the session or it can be a distributed transaction in which the
		session is enlisted. This status bit MUST NOT be set in conjunction with the RESETCONNECTION bit.
		Otherwise identical to RESETCONNECTION.
	*/

	// Second byte dictates whether this is the end of the message
	header := make([]byte, 8)
	if _, err := p.buf.Read(header); err != nil {
		return nil, err
	}

	logp.Info("** header: %x", header)

	// Parse header values
	batchType := header[0]
	status := header[1]
	// don't care about these values for the moment. Probably want to output spid
	// packetSize := binary.BigEndian.Uint16(header[2:4])
	// spid := binary.BigEndian.Uint16(header[4:6])

	// We want to create a structure to hold the message if there isn't already one in place
	if status&0x01 == 0x01 {
		// This drives whether the event is published. After each parse we call into trans to merge messages
		msg.isComplete = true
	}

	if status&0x02 == 0x02 && status&0x01 == 0x01 {
		// Ignore message
		logp.Info("** Ignore message")
		return nil, fmt.Errorf("Ignore message")
	}

	// ** Need to understand what to do if we receive 0x08

	// Change the below to StreamName to match spec?
	switch batchType {

	case 0x01:
		p.request.requestType = "SQLBatch"
		msg.IsRequest = true

		// Need to:
		// Read the headers - only on the first packet (atm always assume there are headers)
		// Read and decode the UCS-2 data
		// We can use something similar to the below for data conversions https://play.golang.org/p/8rnqX5ltpeI

		// Need to read 4 bytes (DWORD -> uint32) and decode (littleEndian format)
		head1 := make([]byte, 4)
		if _, err := p.buf.Read(head1); err != nil {
			return msg, err
		}
		headLen := binary.LittleEndian.Uint32(head1)

		// Skip over the header
		p.buf.Advance(int(headLen) - 4)

		// Read the rest of the packet data
		data := make([]byte, p.buf.Len())
		if _, err := p.buf.Read(data); err != nil {
			return msg, err
		}

		// Decode from UCS-2 (bit naughty as using the utf16 decode - see notes)
		r := bytes.NewReader(data)
		x := make([]uint16, len(data)/2)
		binary.Read(r, binary.LittleEndian, x)
		logp.Info("** sql batch: %s", string(utf16.Decode(x)))

	case 0x02:
		p.request.requestType = "Pre-TDS7 Login"
		msg.IsRequest = true
	case 0x03:
		// Can't recreate this from SSMS so will need to write a proggie to exercise RPC
		p.request.requestType = "RPC"
		msg.IsRequest = true
	case 0x04:
		// NB: not really a request type
		p.response.responseType = "Tabular result"
		msg.IsRequest = false

		for p.buf.Len() > 0 {
			// We need to loop around the below and pull off each token as we go
			tokenType, err := p.buf.ReadByte()
			if err != nil {
				return msg, err
			}

			switch tokenType {
			case altMetadataToken:
				return msg, fmt.Errorf("** Not Implemented: altMetadataToken 0x%x", tokenType)
			case altRowToken:
				return msg, fmt.Errorf("** Not Implemented: altRowToken 0x%x", tokenType)
			case colMetadataToken:
				logp.Info("** colMetadataToken 0x%x", tokenType)

				// Column Count USHORT (unsigned 2 byte int)
				cCount := make([]byte, 2)
				if _, err := p.buf.Read(cCount); err != nil {
					return msg, err
				}
				columnCount := binary.LittleEndian.Uint16(cCount)
				logp.Info("** Column Count: %d", columnCount)

				// CekTable???? -->
				cCekTable := make([]byte, 2)
				if _, err := p.buf.Read(cCekTable); err != nil {
					return msg, err
				}
				logp.Info("** cekTable?: x%x", cCekTable)

				if p.response.colDataTypes, err = parseColumnMetadata(p, int(columnCount)); err != nil {
					return msg, err
				}
				logp.Info("** colDataTypes: %v", p.response.colDataTypes)

			case colInfoToken:
				return msg, fmt.Errorf("** Not Implemented: colInfoToken %v", tokenType)
			case dataClassificationToken:
				return msg, fmt.Errorf("** Not Implemented: dataClassificationToken %v", tokenType)
			case doneToken:
				// Revisit this - just skip to the end for the moment
				p.buf.Advance(p.buf.Len())
			case doneProcToken:
				return msg, fmt.Errorf("** Not Implemented: doneProcToken %v", tokenType)
			case doneInProcToken:
				return msg, fmt.Errorf("** Not Implemented: doneInProcToken %v", tokenType)
			case envChangeToken:
				return msg, fmt.Errorf("** Not Implemented: envChangeToken %v", tokenType)
			case errorToken:
				return msg, fmt.Errorf("** Not Implemented: errorToken %v", tokenType)
			case featureExtackToken:
				return msg, fmt.Errorf("** Not Implemented: featureExtackToken %v", tokenType)
			case fedAuthInfoToken:
				return msg, fmt.Errorf("** Not Implemented: fedAuthInfoToken %v", tokenType)
			case infoToken:
				return msg, fmt.Errorf("** Not Implemented: infoToken %v", tokenType)
			case loginAckToken:
				return msg, fmt.Errorf("** Not Implemented: loginAckToken %v", tokenType)
			case nbcRowToken:
				/*
					Page 106:
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

				// So to decide how many bytes we need to read we need to take the length of column metadata
				// 0  -> 0 byte -- dont' account for this. Pretty sure it's not possible
				// 1  -> 1 byte
				// 2  -> 1 byte
				// 3  -> 1 byte
				// 4  -> 1 byte
				// 5  -> 1 byte
				// 6  -> 1 byte
				// 7  -> 1 byte
				// 8  -> 1 byte
				// 9  -> 2 byte
				// 10 -> 2 byte
				// 11 -> 2 byte

				// Up the row cound
				p.response.rowsReturned++

				// Check out the bits library as think we can do this in one operation
				bytesToRead := len(p.response.colDataTypes) / 8
				// If we don't have a perfect fit then we overflow into another byte
				if len(p.response.colDataTypes)%8 != 0 {
					bytesToRead++
				}

				logp.Info("** bytesToRead: %d", bytesToRead)

				nbc := make([]byte, bytesToRead)
				if _, err := p.buf.Read(nbc); err != nil {
					return msg, err
				}

				// Every column in colMeta has a bit value indicating whether it is present in the row. 1 indicates
				// it is null and is not present

				logp.Info("** nbc: %v", nbc)
				logp.Info("** Columns to process: %v", p.response.colDataTypes)

				// We frankly don't care about reading the values
				// We should just advance the pointer - read them for the time-being
				for i := 0; i < len(p.response.colDataTypes); i++ {

					// Logic based on: https://play.golang.org/p/copjZW4Pl8_r
					// Wrap this in a function and see if we can improve
					// Left most column is the least significant bit. i.e. 00000001 means skip the first column
					nbcIdx := i / 8
					logp.Info("*** nbcIdx: %d", nbcIdx)
					logp.Info("*** nbc[nbcIdx]: %d", nbc[nbcIdx])
					if nbc[nbcIdx]&1 == 1 {
						// Skip column
						logp.Info("*** Skip column: %d", i)
						// Right shift all bits 1
						nbc[nbcIdx] = nbc[nbcIdx] >> 1
						continue
					}
					nbc[nbcIdx] = nbc[nbcIdx] >> 1
					logp.Info("*** Process column: %d", i)

					advanceBufferForDataType(p, p.response.colDataTypes[i])
				}
			case offsetToken:
				return msg, fmt.Errorf("** Not Implemented: offsetToken %v", tokenType)
			case orderToken:
				return msg, fmt.Errorf("** Not Implemented: orderToken %v", tokenType)
			case returnStatusToken:
				return msg, fmt.Errorf("** Not Implemented: returnStatusToken %v", tokenType)
			case returnValueToken:
				return msg, fmt.Errorf("** Not Implemented: returnValueToken %v", tokenType)
			case rowToken:
				p.response.rowsReturned++

				for i := 0; i < len(p.response.colDataTypes); i++ {
					advanceBufferForDataType(p, p.response.colDataTypes[i])
				}
			case sessionStateToken:
				return msg, fmt.Errorf("** Not Implemented: sessionStateToken %v", tokenType)
			case sspiToken:
				return msg, fmt.Errorf("** Not Implemented: sspiToken %v", tokenType)
			case tabNameToken:
				return msg, fmt.Errorf("** Not Implemented: tabnameToken %v", tokenType)
			default:
				return msg, fmt.Errorf("Unrecognised Token")
			}
		}

		// Read the rest of the packet data
		if p.buf.Len() > 0 {
			data := make([]byte, p.buf.Len())
			if _, err := p.buf.Read(data); err != nil {
				return msg, err
			}
			logp.Info("** remaining buffer: %v", data)
		}

		// case 0x05:
	// 	logp.Info("* Type: Unused")
	case 0x06:
		p.request.requestType = "Attention Signal"
		msg.IsRequest = true
	case 0x07:
		p.request.requestType = "Bulk load data"
		msg.IsRequest = true
	case 0x08:
		p.request.requestType = "Federated Authentication Token"
		msg.IsRequest = true
	// case 0x09, 0x0A, 0x0B, 0x0C, 0x0D:
	// 	logp.Info("* Type: Unused")
	case 0x0E:
		p.request.requestType = "Transaction Manager Request"
		msg.IsRequest = true
	// case 0x0F:
	// 	logp.Info("* Type: Unused")
	case 0x10:
		p.request.requestType = "TDS7 Login"
		msg.IsRequest = true
	case 0x20:
		p.request.requestType = "SSPI"
		msg.IsRequest = true
	case 0x30:
		p.request.requestType = "Pre-Login"
		msg.IsRequest = true
	default:
		return nil, fmt.Errorf("Unrecognised TDS Type")
	}

	// Mark buffer as read (even if it's not)
	p.buf.Advance(p.buf.Len())

	// Move into a build fields function or similar
	if msg.isComplete {
		logp.Info("msg.isComplete")
		if msg.IsRequest {
			logp.Info("msg.IsRequest")
			msg.request = &mssqlRequest{
				requestType: p.request.requestType,
			}
		} else {
			logp.Info("msg.IsResponse")
			msg.response = &mssqlResponse{
				responseType: p.response.responseType,
				rowsReturned: p.response.rowsReturned,
			}
		}
		p.request = nil
		p.response = nil
		logp.Info("msg.request: %v", msg.request)
		logp.Info("msg.response: %v", msg.response)
	}

	return msg, nil
}

func parseColumnMetadata(p *parser, columnCount int) (colMeta []byte, err error) {

	colMeta = make([]byte, columnCount)

	for i := 0; i < columnCount; i++ {

		/* UserType:
		The user type ID of the data type of the column. Depending on the TDS version that is used, valid values are 0x0000 or 0x00000000,
		with the exceptions of data type TIMESTAMP (0x0050 or 0x00000050) and alias types (greater than 0x00FF or 0x000000FF).
		*/
		uType := make([]byte, 4)
		if _, err := p.buf.Read(uType); err != nil {
			return colMeta, err
		}
		logp.Info("** UserType: 0x%x", uType)

		/* Flags:
		The size of the Flags parameter is always fixed at 16 bits regardless of the TDS version.
		Each of the 16 bits of the Flags parameter is interpreted based on the TDS version negotiated during login.
		Bit flags, in least significant bit order (FLAGRULE = F0 F1 F2 F3 F4 F5 F6 F7 : would be observed on the wire in the natural value order F7F6F5F4F3F2F1F0)

		So the wire value order is: (actually this might be the wrong way round)
		DOUBLE CHECK THE SPEC ON THE BELOW... Confusing
		18:		fNullableUnknown is a bit flag. Its value is 1 if it is unknown whether the column might be nullable.
		17:		fKey is a bit flag. Its value is 1 if the column is part of a primary key for the row and the T-SQL SELECT statement contains FOR BROWSE.
		16:		fHidden is a bit flag. Its value is 1 if the column is part of a hidden primary key created to support a T-SQL SELECT statement
				containing FOR BROWSE.<37>
		12-15:	uReserved (4-bit)
		11:		fFixedLenCLRType is a bit flag. Its value is 1 if the column is a fixed-length common language runtime user-defined type (CLR UDT).
		10:		usReserverd3
		9:		fEncrypted is a bit flag. Its value is 1 if the column is encrypted transparently and has to be decrypted to view the plaintext value. This flag is valid when the column encryption feature is negotiated between client and server and is turned on.
		8:		fSparseColumnSet, introduced in TDS version 7.3.B, is a bit flag. Its value is 1 if the column is the special XML column for the sparse column set. For information about using column sets, see [MSDN-ColSets].
		8:      fFixedLenCLRType
		6-7:	usReservedODBC is a 2-bit field that is used by ODS gateways supporting the ODBC ODS gateway driver.
		5: 		fComputed is a bit flag. Its value is 1 if the column is a COMPUTED column.
		4: 		fIdentity is a bit flag. Its value is 1 if the column is an identity column.
		2-3:	usUpdateable is a 2-bit field. Its value is 0 if column is read-only, 1 if column is read/write and 2 if updateable is unknown.
		1:		fCaseSen is a bit flag. Set to 1 for string columns with binary collation and always for the XML data type. Set to 0 otherwise
		0:		fNullable is a bit flag. Its value is 1 if the column is nullable
		*/
		flags := make([]byte, 2)
		if _, err := p.buf.Read(flags); err != nil {
			return colMeta, err
		}

		logp.Info("** flags: 0x%x", flags)

		// if i == 0 {
		// 	// Type BYTE - NumParts (Don't think this is numParts. This is the datatype for varchars (167))
		// 	numParts, err := p.buf.ReadByte()
		// 	if err != nil {
		// 		return err
		// 	}
		// 	logp.Info("** numParts: 0x%x", numParts)

		// 	/* US_VARCHAR = USHORTLEN *CHAR
		// 	   USHORTLEN = An unsigned 2-byte (16-bit) value representing the length of the associated data. The range is 0 to 65535.
		// 	Variable-length character streams are defined by a length field followed by the data itself. There are two types of variable-length character streams,
		// 	each dependent on the size of the length field (for example, a BYTE or USHORT). If the length field is zero, then no data follows the length field.
		// 	Note that the lengths of B_VARCHAR and US_VARCHAR are given in Unicode characters.
		// 	*/

		// 	// NOTE: If the below is anything other than 0 we need to be reading the TableName
		// 	partNameLength, err := p.buf.ReadByte()
		// 	if err != nil {
		// 		return err
		// 	}
		// 	if partNameLength != 0 {
		// 		return fmt.Errorf("Not Implemented: Received table name and unable to parse")
		// 	}
		// 	logp.Info("** partNameLength: 0x%x", partNameLength)
		// }

		// [CryptoMetaData] -? Optional - read up about this

		// DataType:

		dataType, err := p.buf.ReadByte()
		if err != nil {
			return colMeta, err
		}
		logp.Info("** dataType: 0x%x", dataType)

		colMeta[i] = dataType

		// Remove in favour of columnMeta
		var columnName string

		switch dataType {
		// Fixed length data types - all non-nullable.
		// Don't need to list all of these. Check docs as should be able to apply bitmask
		case
			nulltype, int1type, bittype, int2type, int4type, datetim4type, flt4type, moneytype,
			datetimetype, flt8type, money4type, int8type:

			columnName, err = parseColumnName(p)
			if err != nil {
				return colMeta, err
			}

		case intntype: // 1, 2, 4 & 8 mapping from tinyint -> bigint respectively
			size, err := p.buf.ReadByte()
			if err != nil {
				return colMeta, err
			}
			logp.Info("** int size: 0x%x", size)

			columnName, err = parseColumnName(p)
			if err != nil {
				return colMeta, err
			}

		case bigvarchartype, nvarchartype: // 5-byte COLLATION, followed by a 2-byte max length (same for varchar & nchar)
			ignore := make([]byte, 7)
			if _, err := p.buf.Read(ignore); err != nil {
				return colMeta, err
			}
			// todo: work out what this represents (collation?)
			logp.Info("** ignore: 0x%x", ignore)

			columnName, err = parseColumnName(p)
			if err != nil {
				return colMeta, err
			}

		default:
			return colMeta, fmt.Errorf("Unhandled data type: x%x", dataType)
		}

		logp.Info("columnName: %s", columnName)

	}

	return colMeta, nil
}

// This could be more generic. No need to be specific to column names
func parseColumnName(p *parser) (columnName string, err error) {
	// ColName = B_VARCHAR
	// Byte representing the length followed by the column name
	cNameLength, err := p.buf.ReadByte()
	if err != nil {
		return "", err
	}
	logp.Info("** cNameLength: 0x%x", cNameLength)

	cName := make([]byte, cNameLength*2)
	if _, err := p.buf.Read(cName); err != nil {
		return "", err
	}

	logp.Info("** cName: 0x%x, len: %d", cName, len(cName))

	r := bytes.NewReader(cName)
	x := make([]uint16, len(cName)/2)
	binary.Read(r, binary.LittleEndian, x)
	logp.Info("** x: %v len: %d", x, len(x))
	columnName = string(utf16.Decode(x))

	return columnName, nil
}

// todo: rename this function
// todo: support all data types
func advanceBufferForDataType(p *parser, dataType byte) error {
	switch dataType {
	// case 			nulltype, int1type, bittype, int2type, int4type, datetim4type, flt4type, moneytype,
	// datetimetype, flt8type, money4type, int8type:
	case int1type:
		p.buf.Advance(1)
	case int2type:
		p.buf.Advance(2)
	case int4type:
		p.buf.Advance(4)
	case int8type:
		p.buf.Advance(8)
	case intntype:
		len, err := p.buf.ReadByte() // First byte specifies length
		if err != nil {
			return err
		}
		p.buf.Advance(int(len))
	case varchartype, bigvarchartype, nvarchartype, nchartype:
		cCount := make([]byte, 2)
		if _, err := p.buf.Read(cCount); err != nil {
			return err
		}
		charCount := binary.LittleEndian.Uint16(cCount)
		if err := p.buf.Advance(int(charCount)); err != nil {
			return err
		}
	}
	return fmt.Errorf("** Unhandled data type %x", dataType)
}
