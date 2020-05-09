package tds

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

type parser struct {
	buf     streambuf.Buffer
	config  *parserConfig
	message *message

	onMessage func(m *message) error
}

type parserConfig struct {
	maxBytes int
}

type message struct {
	applayer.Message

	// indicator for parsed message being complete or requires more messages
	// (if false) to be merged to generate full message.
	isComplete bool

	// list element use by 'transactions' for correlation
	next *message

	// neaten this up:
	requestType string
}

// Error code if stream exceeds max allowed size on append.
var (
	ErrStreamTooLarge = errors.New("Stream data too large")
)

/*
	   (ZL) Zero Length Token(xx01xxxx)
	    This class of token is not followed by a length specification. There is no data associated with the token.

	   (FL) Fixed Length Token(xx11xxxx)
		This class of token is followed by 1, 2, 4, or 8 bytes of data.
		No length specification follows this token because the length of its associated data is encoded in the token itself.
		The different fixed data-length token definitions take the form of one of the following bit sequences,
		depending on whether the token is followed by 1, 2, 4, or 8 bytes of data. Also in the table, a value of “0 or 1” denotes a bit position that can
		contain the bit value “0” or “1”.
		(xx01xxxx) - 1 byte of data
		(xx11xxxx) - 2 byte of data
		(xx10xxxx) - 4 byte of data
		(xx00xxxx) - 8 byte of data

	   Fixed-length tokens are used by the following data types: bigint, int, smallint, tinyint, float, real, money, smallmoney, datetime, smalldatetime, and bit.
		The type definition is always represented in COLMETADATA and ALTMETADATA data streams as a single byte Type.

	   (VL) Variable Length Tokens(xx10xxxx)
		This class of token definition is followed by a count of the number of fields that follow the token.
		Each field length is dependent on the token type. The total length of the token can be determined only by walking the fields

	   (VC) Variable Count Tokens(xx00xxxx)
		This class of token definition is followed by a count of the number of fields that follow the token.
		Each field length is dependent on the token type. The total length of the token can be determined only by walking the fields.
*/

// token types
const (
	altMetadataToken        = 0x88 // (variable columns)
	altRowToken             = 0xd3 // (zero length)
	colMetadataToken        = 0x81 // (variable columns)
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

func (p *parser) init(
	cfg *parserConfig,
	onMessage func(*message) error,
) {
	logp.Info("parser.init()")
	*p = parser{
		buf:       streambuf.Buffer{},
		config:    cfg,
		onMessage: onMessage,
	}
}

func (p *parser) append(data []byte) error {
	logp.Info("parser.append()")
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
	logp.Info("parser.feed()")
	if err := p.append(data); err != nil {
		return err
	}

	for p.buf.Total() > 0 {
		if p.message == nil {
			// allocate new message object to be used by parser with current timestamp
			p.message = p.newMessage(ts)
		}

		msg, err := p.parse()
		if err != nil {
			logp.Info("** parse returned error: %s", err)
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
		if err := p.onMessage(msg); err != nil {
			return err
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
	To implement messages on top of existing, arbitrary transport layers, a packet header is included as part of the packet.
	The packet header precedes all data within the packet. It is always 8 bytes in length.
	Most importantly, the packet header states the Type and Length of the entire packet. */

	/*
		Packet data for a given message follows the packet header (see Type in section 2.2.3.1.1 for messages that contain packet data).
		As previously stated, a message can span more than one packet. Because each new message MUST always begin within a new packet,
		a message that spans more than one packet only occurs if the data to be sent exceeds the maximum packet data size,
		which is computed as (negotiated packet size - 8 bytes), where the 8 bytes represents the size of the packet header.
	*/

	// Byte	Usage
	// 1	Type
	// 2	Status
	// 3,4	Length
	// 5,6	SPID
	// 7	PacketId -- currently ignored (might be worth parsing for multi-packet messages)
	// 8	Unused

	// Split out a function to process the packet header?

	msg := p.message
	// Empty buffer - need to decide what to do here
	if p.buf.Len() < 8 {
		logp.Info("* Empty(ish) buffer")
		return nil, nil
	}

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

	// Parse header values
	batchType := header[0]
	status := header[1]
	packetSize := binary.BigEndian.Uint16(header[2:4])
	spid := binary.BigEndian.Uint16(header[4:6])

	if status&0x01 != 0x01 {
		// Need to understand what to do here
		logp.Info("** Not end of message")
		return nil, fmt.Errorf("Not end of message -> still to implement")
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
		msg.requestType = "SQLBatch"
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
		msg.requestType = "Pre-TDS7 Login"
		msg.IsRequest = true
	case 0x03:
		// Can't recreate this from SSMS so will need to write a proggie to exercise RPC
		msg.requestType = "RPC"
		msg.IsRequest = true
	case 0x04:
		// NB: not really a request type
		msg.requestType = "Tabular result"
		msg.IsRequest = false

		tokenType, err := p.buf.ReadByte()
		if err != nil {
			return msg, err
		}

		switch tokenType {
		case altMetadataToken:
			logp.Info("** altMetadataToken %v", tokenType)
		case altRowToken:
			logp.Info("** altRowToken %v", tokenType)
		case colMetadataToken:
			logp.Info("** colMetadataToken %v", tokenType)

			// Column Count USHORT (unsigned 2 byte int)
			cCount := make([]byte, 2)
			if _, err := p.buf.Read(cCount); err != nil {
				return msg, err
			}
			columnCount := binary.LittleEndian.Uint16(cCount)
			logp.Info("** Column Count: %d", columnCount)

		case colInfoToken:
			logp.Info("** colInfoToken %v", tokenType)
		case dataClassificationToken:
			logp.Info("** dataClassificationToken %v", tokenType)
		case doneToken:
			logp.Info("** doneToken %v", tokenType)
		case doneProcToken:
			logp.Info("** doneProcToken %v", tokenType)
		case doneInProcToken:
			logp.Info("** doneInProcToken %v", tokenType)
		case envChangeToken:
			logp.Info("** envChangeToken %v", tokenType)
		case errorToken:
			logp.Info("** errorToken %v", tokenType)
		case featureExtackToken:
			logp.Info("** featureExtackToken %v", tokenType)
		case fedAuthInfoToken:
			logp.Info("** fedAuthInfoToken %v", tokenType)
		case infoToken:
			logp.Info("** infoToken %v", tokenType)
		case loginAckToken:
			logp.Info("** loginAckToken %v", tokenType)
		case nbcRowToken:
			logp.Info("** nbcRowToken %v", tokenType)
		case offsetToken:
			logp.Info("** offsetToken %v", tokenType)
		case orderToken:
			logp.Info("** orderToken %v", tokenType)
		case returnStatusToken:
			logp.Info("** returnStatusToken %v", tokenType)
		case returnValueToken:
			logp.Info("** returnValueToken %v", tokenType)
		case rowToken:
			logp.Info("** rowToken %v", tokenType)
		case sessionStateToken:
			logp.Info("** sessionStateToken %v", tokenType)
		case sspiToken:
			logp.Info("** sspiToken %v", tokenType)
		case tabNameToken:
			logp.Info("** tabnameToken %v", tokenType)
		default:
			return msg, fmt.Errorf("Unrecognised Token")
		}

		// Read the rest of the packet data
		data := make([]byte, p.buf.Len())
		if _, err := p.buf.Read(data); err != nil {
			return msg, err
		}

		logp.Info("** tabular result: %v", data)

	// case 0x05:
	// 	logp.Info("* Type: Unused")
	case 0x06:
		msg.requestType = "Attention Signal"
		msg.IsRequest = true
	case 0x07:
		msg.requestType = "Bulk load data"
		msg.IsRequest = true
	case 0x08:
		msg.requestType = "Federated Authentication Token"
		msg.IsRequest = true
	// case 0x09, 0x0A, 0x0B, 0x0C, 0x0D:
	// 	logp.Info("* Type: Unused")
	case 0x0E:
		msg.requestType = "Transaction Manager Request"
		msg.IsRequest = true
	// case 0x0F:
	// 	logp.Info("* Type: Unused")
	case 0x10:
		msg.requestType = "TDS7 Login"
		msg.IsRequest = true
	case 0x20:
		msg.requestType = "SSPI"
		msg.IsRequest = true
	case 0x30:
		msg.requestType = "Pre-Login"
		msg.IsRequest = true
	default:
		return nil, fmt.Errorf("Unrecognised TDS Type")
	}

	logp.Info("** packetSize: %d", packetSize)
	logp.Info("** spid: %d", spid)
	logp.Info("** requestType: %s", msg.requestType)

	// Mark buffer as read (even if it's not)
	p.buf.Advance(p.buf.Len())

	return msg, nil
}
