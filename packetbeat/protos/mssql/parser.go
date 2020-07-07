package mssql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/elastic/beats/v7/libbeat/common/streambuf"
	"github.com/elastic/beats/v7/packetbeat/protos/applayer"
)

type messageHeader struct {
	messageType   byte
	messageStatus byte
}

type parserConfig struct {
	maxBytes int
}

type message struct {
	applayer.Message
	header *messageHeader

	colDataTypes []byte
	rowsReturned int
	resultSets   int
	sqlBatch     string
	procName     string
}

type parser struct {
	config *parserConfig

	buf     streambuf.Buffer
	sqlConn *sqlConnection // Required to indicate whether column encryption has been negotiated. Affects how we parse colmeta
	message *message

	onMessage func(m *message) error
}

// todo: Add in relevant error codes
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
	if _, err := p.buf.Write(data[headerLen:]); err != nil {
		return err
	}

	if p.config.maxBytes > 0 && p.buf.Total() > p.config.maxBytes {
		return ErrStreamTooLarge
	}
	return nil
}

func (p *parser) feed(ts time.Time, data []byte, requestType byte, connInfo *sqlConnection) error {

	if len(data) < headerLen {
		return nil
	}

	if p.message == nil {
		p.message = p.newMessage(ts)
	}

	p.parseHeader(data)

	// This will append the data portion of the packet (minus the header)
	if err := p.append(data); err != nil {
		return err
	}

	// Wait for more data if incomplete
	if !isComplete(p.message.header) {
		return nil
	}

	if ignoreMessage(p.message.header) {
		return fmt.Errorf("Header indicates to ignore message")
	}

	p.sqlConn = connInfo

	if err := p.parse(requestType); err != nil {
		debugf("parse error. Header: %v", p.message.header)
		// On error read the previous 32 bytes and the next 32 bytes
		consumed := p.buf.BufferConsumed()
		if consumed > 32 {
			consumed = 32
		}
		consumedBuffer := make([]byte, consumed)
		p.buf.Advance(consumed * -1)
		p.buf.Read(consumedBuffer)
		debugf("parse error. Previous %d bytes in buffer: % x", consumed, consumedBuffer)

		remaining := p.buf.Len()
		if remaining > 16 {
			remaining = 16
		}
		remainingBuffer := make([]byte, remaining)
		p.buf.Read(remainingBuffer)
		debugf("parse error. Next %d bytes in buffer: % x", remaining, remainingBuffer)
		return err
	}

	err := p.onMessage(p.message)

	// Reset the data fields in the parser
	p.buf.Reset()
	p.message.header = &messageHeader{}
	p.message = nil

	return err
}

func (p *parser) newMessage(ts time.Time) *message {
	return &message{
		Message: applayer.Message{
			Ts: ts,
		},
	}
}

func (p *parser) parse(requestType byte) error {
	p.message.IsRequest = true

	switch p.message.header.messageType {
	case preTds7LoginMessage:
		return p.buf.Advance(p.buf.Len())

	case attentionSignalMessage:
		return p.buf.Advance(p.buf.Len())

	case bulkLoadDataMessage:
		return p.buf.Advance(p.buf.Len())

	case federatedAuthenticationTokenMesage:
		return p.buf.Advance(p.buf.Len())

	case transactionManagerRequestMessage:
		return p.buf.Advance(p.buf.Len())

	case tds7LoginMessage:
		return p.buf.Advance(p.buf.Len())

	case sspiMessage:
		return p.buf.Advance(p.buf.Len())

	case preLoginMessage:
		return p.buf.Advance(p.buf.Len())

	// Only parse the data for batch, rpc & result messages:
	case sqlBatchMessage:
		err := p.advanceAllHeaders()
		if err != nil {
			return err
		}
		// Read the rest of the packet data
		p.message.sqlBatch, err = p.readUCS2String(p.buf.Len())
		return err

	case rpcMessage:
		if err := p.advanceAllHeaders(); err != nil {
			return err
		}

		nameLen, err := p.readUInt16(littleEndian)
		if err != nil {
			return err
		}

		// 0xFFFF represents a proc id
		if int(nameLen) != 65535 {
			if p.message.procName, err = p.readUCS2String(int(nameLen) * 2); err != nil {
				return err
			}
		}
		return p.buf.Advance(p.buf.Len())

	case tabularResultMessage:
		p.message.IsRequest = false

		if requestType == preLoginMessage || requestType == attentionSignalMessage {
			return p.buf.Advance(p.buf.Len())
		}

		return parseTokenStream(p)
	}

	return fmt.Errorf("Unrecognised message type: 0x%x", p.message.header.messageType)
}

func parseTokenStream(p *parser) error {
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
			if p.sqlConn.columnEncryption == true {
				p.buf.Advance(2)
			}

			if p.message.colDataTypes, err = readColumnMetadata(p, int(columnCount)); err != nil {
				return err
			}
		case colInfoToken:
			return fmt.Errorf("Not Implemented: colInfoToken 0x%x", tokenType)
		case dataClassificationToken:
			return fmt.Errorf("Not Implemented: dataClassificationToken 0x%x", tokenType)
		case doneToken:
			if err := p.buf.Advance(12); err != nil {
				return err
			}
			p.message.resultSets++
		case doneProcToken:
			if err := p.buf.Advance(12); err != nil {
				return err
			}
		case doneInProcToken:
			if err := p.buf.Advance(12); err != nil {
				return err
			}
		case envChangeToken:
			if err := p.advanceVarbyte16(); err != nil {
				return err
			}
		case errorToken:
			if err := p.advanceVarbyte16(); err != nil {
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
					p.sqlConn.columnEncryption = true
				}
				// Now just advance the buffer
				if err := p.advanceVarbyte32(); err != nil {
					return err
				}
			}
		case infoToken:
			if err := p.advanceVarbyte16(); err != nil {
				return err
			}
		case loginAckToken:
			if err := p.advanceVarbyte16(); err != nil {
				return err
			}
		case nbcRowToken:
			// NBCROW (null bitmap compression) 2.2.7.15:
			// Logic loosely based on: https://play.golang.org/p/copjZW4Pl8_r
			p.message.rowsReturned++

			bitmapLen := len(p.message.colDataTypes) / 8
			if len(p.message.colDataTypes)%8 != 0 {
				bitmapLen++
			}

			bitmaps := make([]byte, bitmapLen)
			if _, err := p.buf.Read(bitmaps); err != nil {
				return err
			}

			for i := 0; i < len(p.message.colDataTypes); i++ {
				idx := i / 8
				if bitmaps[idx]&1 != 1 {
					if err := advanceRowValue(p, p.message.colDataTypes[i]); err != nil {
						return err
					}
				}
				bitmaps[idx] = bitmaps[idx] >> 1
			}
		case orderToken:
			if err := p.advanceVarbyte16(); err != nil {
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
				if err := advanceRowValue(p, p.message.colDataTypes[i]); err != nil {
					return err
				}
			}
		case sessionStateToken:
			if err := p.advanceVarbyte32(); err != nil {
				return err
			}
		case sspiToken:
			if err := p.advanceVarbyte16(); err != nil {
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

func readColumnMetadata(p *parser, columnCount int) (colType []byte, err error) {
	// 2.2.7.4 - COLMETADATA token
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
		case intntype, bitntype, datetimntype, fltntype, moneyntype, guidtype, timentype:
			// 1-byte length
			if err = p.buf.Advance(1); err != nil {
				return colType, err
			}

		case ssvarianttype:
			// 4-byte info
			if err = p.buf.Advance(4); err != nil {
				return colType, err
			}

		case bigvarchartype, nvarchartype:
			// 5-byte collation (2.2.5.1.2), followed by 2-byte max length
			if err = p.buf.Advance(7); err != nil {
				return colType, err
			}

		case decimaltype, numerictype, decimalntype, numericntype, datetime2ntype,
			datetimeoffsetntype, chartype, binarytype, varbinarytype, bigvarbinarytype,
			bigbinarytype, bigchartype, xmltype, udttype, texttype, imagetype, ntexttype:

			return colType, fmt.Errorf("Parse Metadata. Not implemented data type: x%x", colType[i])
		}

		if _, err = readColumnName(p); err != nil {
			return
		}
	}

	return colType, nil
}

func ignoreMessage(header *messageHeader) bool {
	return header.messageStatus&ignoreStatus == ignoreStatus && header.messageStatus&eomStatus == eomStatus
}

func isComplete(header *messageHeader) bool {
	return header.messageStatus&eomStatus == eomStatus
}

func (p *parser) parseHeader(data []byte) {
	p.message.header = &messageHeader{
		messageType:   data[0],
		messageStatus: data[1],
	}
}

func (p *parser) advanceAllHeaders() error {
	headerLen, err := p.readUInt32(littleEndian)
	if err != nil {
		return err
	}
	return p.buf.Advance(int(headerLen) - 4)
}

func advanceRowValue(p *parser, dataType byte) error {
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

func (p *parser) advanceVarbyte16() (err error) {
	len, err := p.readUInt16(littleEndian)
	if err != nil {
		return err
	}
	return p.buf.Advance(int(len))
}

func (p *parser) advanceVarbyte32() (err error) {
	len, err := p.readUInt32(littleEndian)
	if err != nil {
		return err
	}
	return p.buf.Advance(int(len))
}

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
