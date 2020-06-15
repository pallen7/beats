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
MVP todo list:
- Fix bug where we can't process 1000 rows (recieve a parser.eof error)
-- So:
Row values can be spread over multiple packets
Also applies to nbc rows
This can't apply to the header
Double check the spec to see if it's specified the message and token types this can apply to

d1 = row token:
1020   2b 03 00 00 d1 2d 03 00 00 04 2c 03 00 00 d1 2e
1030   03 00 00 04 2d 03 00 00 d1 2f 03 00 00 04 2e 03
So the last row token shows a 4 byte int. And then a variable int of length 4 with only the first 2 bytes

Start of the next TDS packet
First 8 bytes are the packet header and then we have the 00 00 to conclude the last 2 bytes of the previous packet row
0040   04 01 07 51 00 35 03 00 00 00 d1 30 03 00 00 04
0050   2f 03 00 00 d1 31 03 00 00 04 30 03 00 00 d1 32

I think we need to read the data length from the header.
Before we commence any read operation we should check the buffer.len() (inexpensive as this is just an int held in the buffer) and then if there aren't
enough bytes in the buffer to carry out the read that we are expecting then do 'something'. Possibly just create a byte slice of what is left on the
parser and then stick that onto the rest of the value that we read from the next packet

--->>> First action:
Can we just wait to see if this is the end of the message and if it isn't then just wait for the next message and append the buffer until
we have all data?

** Dig through the other protocols to see if this is what they do. Looks like that's the caes for mongodb. Look at Mysql

Max bytes = 10485760 = 10mb
Default packet size for TDS packets is 4096 (-8 bytes for the header = 4088)
We could process 2.5k packets before reaching max bytes

2.2.3.1.3 Length
Length is the size of the packet including the 8 bytes in the packet header. It is the number of bytes from the start of this header to the start of the next packet header.
Length is a 2-byte, unsigned short int and is represented in network byte order (big-endian).
The Length value MUST be greater than or equal to 512 bytes and smaller than or equal to 32,767 bytes. The default value is 4,096 bytes.
Starting with TDS 7.3, the Length MUST be the negotiated packet size when sending a packet from client to server, unless it is the last packet of a request
(that is, the EOM bit in Status is ON) or the client has not logged in.

2.2.3.2 Packet Data
Packet data for a given message follows the packet header (see Type in section 2.2.3.1.1 for messages that contain packet data).
As previously stated, a message can span more than one packet. Because each new message MUST always begin within a new packet,
a message that spans more than one packet only occurs if the data to be sent exceeds the maximum packet data size, which is computed as
(negotiated packet size - 8 bytes), where the 8 bytes represents the size of the packet header.
If a stream spans more than one packet, then the EOM bit of the packet header Status code MUST be set to 0 for every packet header.
The EOM bit MUST be set to 1 in the last packet to signal that the stream ends. In addition,


- Add the ECS fields into pub.go/trans.go
- Support all type in response datasets
- Neaten up the parser functions (i.e. create parseHeader)
- We (probably) need to 'properly' convert UCS-2 (instead of just using the default UTF-16 decoding)
- Validate the header details match between separate packets
- Add support for RPC calls
- Add tests
- Create a specification file and add all of the constants (and ones for the headers) into there (doesn't seem to be idiomatic)
*/

type messageHeader struct {
	messageType byte
	status      byte
	// length	int (bytes 3&4)
	// spid 	(bytes 5&6)
	// packetId	(byte 7)

}

type parser struct {
	buf       streambuf.Buffer
	config    *parserConfig
	message   *message
	onMessage func(m *message) error
	header    messageHeader
}

type parserConfig struct {
	maxBytes int
}

// It doesn't represent an individual packet that's being processed but a complete message request or response
type message struct {
	// Set these variables based on the first request that we get
	applayer.Message

	isComplete bool

	messageType  string
	colDataTypes []byte
	rowsReturned int
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
	//_, err := p.buf.Write(data[8:])
	if _, err := p.buf.Write(data[8:]); err != nil {
		return err
	}

	if p.config.maxBytes > 0 && p.buf.Total() > p.config.maxBytes {
		return ErrStreamTooLarge
	}
	return nil
}

func (p *parser) feed(ts time.Time, data []byte) error {

	if len(data) < 8 {
		// todo: not sure if empty buffer should be an error
		return fmt.Errorf("Empty(ish) buffer")
	}

	// We need to parse the header at this point and only append the data
	header, err := parseHeaderRaw(data)
	if err != nil {
		return err
	}

	// Validate the header - check that the header we now have reflects what we were previously processing (if we were already processing)

	// Once validated then set the parse header
	p.header = header

	// This will append the data portion of the packet
	if err := p.append(data); err != nil {
		return err
	}

	// Not sure if this should be an error?
	if ignoreMessage(p.header) {
		return fmt.Errorf("Ignoring message")
	}

	// Crack on and get some more data
	if !isComplete(p.header) {
		logp.Info("** Waiting for more data")
		return nil
	}

	// todo: Effectively we only call into this once for a complete message even if it is made up of various packets
	// newMessage creates an appPlayer message containing all of our core fields. Do we need to care about merging messages
	// together as we need to capture 'core' information from various packets. Currently we will take the 'core' fields
	// from the last packet as we only process on completion of a message so this feels wrong

	// why is this in a for loop?
	for p.buf.Total() > 0 {

		// todo: This should be pulled right up to the top of this function as we want to do this when we receive the first packet
		if p.message == nil {
			// allocate new message object to be used by parser with current timestamp
			p.message = p.newMessage(ts)
		}

		err := p.parse()
		if err != nil {
			logp.Info("** parse returned error: %s", err)

			// Read the rest of the buffer data - no need to check for errors
			data := make([]byte, p.buf.Len())
			p.buf.Read(data)
			logp.Info("** remaining data in buffer: %v", data)

			return err
		}
		// This will now never be nil
		if p.message.messageType == "" {
			logp.Info("** nil message parsed")
			break // wait for more data
		}

		// Do we need this? We should only ever reach here when we have completely processed a message
		p.buf.Reset()

		if err := p.onMessage(p.message); err != nil {
			p.message = nil
			return err
		}
		p.message = nil
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

func (p *parser) parse() error {
	// header, err := parseHeader(p)
	// if err != nil {
	// 	return err
	// }

	switch p.header.messageType {
	case sqlBatchMessage:
		p.message.messageType = "SQLBatch"
		p.message.IsRequest = true

		// Need to:
		// Read the headers - only on the first packet (atm always assume there are headers)
		// Read and decode the UCS-2 data
		// We can use something similar to the below for data conversions https://play.golang.org/p/8rnqX5ltpeI

		// Need to read 4 bytes (DWORD -> uint32) and decode (littleEndian format)
		head1 := make([]byte, 4)
		if _, err := p.buf.Read(head1); err != nil {
			return err
		}
		headLen := binary.LittleEndian.Uint32(head1)

		// Skip over the header
		p.buf.Advance(int(headLen) - 4)

		// Read the rest of the packet data
		data := make([]byte, p.buf.Len())
		if _, err := p.buf.Read(data); err != nil {
			return err
		}

		// Decode from UCS-2 (bit naughty as using the utf16 decode - see notes)
		r := bytes.NewReader(data)
		x := make([]uint16, len(data)/2)
		binary.Read(r, binary.LittleEndian, x)
		logp.Info("** sql batch: %s", string(utf16.Decode(x)))

	case preTds7LoginMessage:
		p.message.messageType = "Pre-TDS7 Login"
		p.message.IsRequest = true
	case rpcMessage:
		// Can't recreate this from SSMS so will need to write a proggie to exercise RPC
		p.message.messageType = "RPC"
		p.message.IsRequest = true
	case tabularResultMessage:
		p.message.messageType = "Tabular result"
		p.message.IsRequest = false

		for p.buf.Len() > 0 {
			// We need to loop around the below and pull off each token as we go
			tokenType, err := p.buf.ReadByte()
			if err != nil {
				return err
			}

			switch tokenType {
			case altMetadataToken:
				return fmt.Errorf("** Not Implemented: altMetadataToken 0x%x", tokenType)
			case altRowToken:
				return fmt.Errorf("** Not Implemented: altRowToken 0x%x", tokenType)
			case colMetadataToken:
				logp.Info("** colMetadataToken 0x%x", tokenType)

				// Column Count USHORT (unsigned 2 byte int)
				cCount := make([]byte, 2)
				if _, err := p.buf.Read(cCount); err != nil {
					return err
				}
				columnCount := binary.LittleEndian.Uint16(cCount)
				logp.Info("** Column Count: %d", columnCount)

				// CekTable???? -->
				cCekTable := make([]byte, 2)
				if _, err := p.buf.Read(cCekTable); err != nil {
					return err
				}
				logp.Info("** cekTable?: x%x", cCekTable)

				if p.message.colDataTypes, err = parseColumnMetadata(p, int(columnCount)); err != nil {
					return err
				}
				logp.Info("** colDataTypes: %v", p.message.colDataTypes)

			case colInfoToken:
				return fmt.Errorf("** Not Implemented: colInfoToken %v", tokenType)
			case dataClassificationToken:
				return fmt.Errorf("** Not Implemented: dataClassificationToken %v", tokenType)
			case doneToken:
				// Revisit this - just skip to the end for the moment
				p.buf.Advance(p.buf.Len())
			case doneProcToken:
				return fmt.Errorf("** Not Implemented: doneProcToken %v", tokenType)
			case doneInProcToken:
				return fmt.Errorf("** Not Implemented: doneInProcToken %v", tokenType)
			case envChangeToken:
				return fmt.Errorf("** Not Implemented: envChangeToken %v", tokenType)
			case errorToken:
				return fmt.Errorf("** Not Implemented: errorToken %v", tokenType)
			case featureExtackToken:
				return fmt.Errorf("** Not Implemented: featureExtackToken %v", tokenType)
			case fedAuthInfoToken:
				return fmt.Errorf("** Not Implemented: fedAuthInfoToken %v", tokenType)
			case infoToken:
				return fmt.Errorf("** Not Implemented: infoToken %v", tokenType)
			case loginAckToken:
				return fmt.Errorf("** Not Implemented: loginAckToken %v", tokenType)
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

				// Up the row count
				p.message.rowsReturned++

				// Check out the bits library as think we can do this in one operation
				bytesToRead := len(p.message.colDataTypes) / 8
				// If we don't have a perfect fit then we overflow into another byte
				if len(p.message.colDataTypes)%8 != 0 {
					bytesToRead++
				}

				logp.Info("** bytesToRead: %d", bytesToRead)

				nbc := make([]byte, bytesToRead)
				if _, err := p.buf.Read(nbc); err != nil {
					return err
				}

				// Every column in colMeta has a bit value indicating whether it is present in the row. 1 indicates
				// it is null and is not present

				logp.Info("** nbc: %v", nbc)
				logp.Info("** Columns to process: %v", p.message.colDataTypes)

				// We frankly don't care about reading the values
				// We should just advance the pointer - read them for the time-being
				for i := 0; i < len(p.message.colDataTypes); i++ {

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

					advanceBufferForDataType(p, p.message.colDataTypes[i])
				}
			case offsetToken:
				return fmt.Errorf("** Not Implemented: offsetToken %v", tokenType)
			case orderToken:
				return fmt.Errorf("** Not Implemented: orderToken %v", tokenType)
			case returnStatusToken:
				return fmt.Errorf("** Not Implemented: returnStatusToken %v", tokenType)
			case returnValueToken:
				return fmt.Errorf("** Not Implemented: returnValueToken %v", tokenType)
			case rowToken:
				p.message.rowsReturned++

				for i := 0; i < len(p.message.colDataTypes); i++ {
					advanceBufferForDataType(p, p.message.colDataTypes[i])
				}
			case sessionStateToken:
				return fmt.Errorf("** Not Implemented: sessionStateToken %v", tokenType)
			case sspiToken:
				return fmt.Errorf("** Not Implemented: sspiToken %v", tokenType)
			case tabNameToken:
				return fmt.Errorf("** Not Implemented: tabnameToken %v", tokenType)
			default:
				return fmt.Errorf("Unrecognised Token: %x", tokenType)
			}
		}

		// Read the rest of the packet data
		if p.buf.Len() > 0 {
			data := make([]byte, p.buf.Len())
			if _, err := p.buf.Read(data); err != nil {
				return err
			}
			logp.Info("** remaining buffer: %v", data)
		}

	case attentionSignalMessage:
		p.message.messageType = "Attention Signal"
		p.message.IsRequest = true
	case bulkLoadDataMessage:
		p.message.messageType = "Bulk load data"
		p.message.IsRequest = true
	case federatedAuthenticationTokenMesage:
		p.message.messageType = "Federated Authentication Token"
		p.message.IsRequest = true
	case transactionManagerRequestMessage:
		p.message.messageType = "Transaction Manager Request"
		p.message.IsRequest = true
	case tds7LoginMessage:
		p.message.messageType = "TDS7 Login"
		p.message.IsRequest = true
	case sspiMessage:
		p.message.messageType = "SSPI"
		p.message.IsRequest = true
	case preLoginMessage:
		p.message.messageType = "Pre-Login"
		p.message.IsRequest = true
	default:
		return fmt.Errorf("Unrecognised message type: %x", p.header.messageType)
	}

	// Mark buffer as read (even if it's not)
	p.buf.Advance(p.buf.Len())

	logp.Info("Finished reading packet")

	return nil
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

func parseHeaderRaw(data []byte) (header messageHeader, err error) {
	header.messageType = data[0]
	header.status = data[1]
	return
}

// Create a header struct to represent this instead of just returning the messageType
func parseHeader(p *parser) (header messageHeader, err error) {

	hBytes := make([]byte, 8)
	if _, err = p.buf.Read(hBytes); err != nil {
		return
	}

	header.messageType = hBytes[0]
	header.status = hBytes[1]
	return
}

func ignoreMessage(header messageHeader) bool {
	return header.status&ignoreStatus == ignoreStatus && header.status&eomStatus == eomStatus
}

func isComplete(header messageHeader) bool {
	return header.status&eomStatus == eomStatus
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
