package tds

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

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
	logp.Info("- data: %s", data)
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
			logp.Info("* New message allocated: %v", p.message)
		}

		msg, err := p.parse()
		logp.Info("* Parsed message: %v", msg)
		if err != nil {
			logp.Info("* parse returned error: %s", err)
			return err
		}
		if msg == nil {
			logp.Info("* parse returned nil msg")
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
	// 7	PacketId -- currently ignored (might be worth parsing)
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
		logp.Info("* Not end of message")
		return nil, fmt.Errorf("Not end of message -> still to implement")
	}

	if status&0x02 == 0x02 && status&0x01 == 0x01 {
		// Ignore message
		logp.Info("* Ignore message")
		return nil, fmt.Errorf("Ignore message")
	}

	// Need to understand what to do if we receive 0x08

	logp.Info("* Processing end of message")

	// Change the below to StreamName to match spec?
	switch batchType {
	case 0x01:
		msg.requestType = "SQLBatch"
		msg.IsRequest = true
	case 0x02:
		msg.requestType = "Pre-TDS7 Login"
		msg.IsRequest = true
	case 0x03:
		msg.requestType = "RPC"
		msg.IsRequest = true
	case 0x04:
		// NB: not really a request type
		msg.requestType = "Tabular result"
		msg.IsRequest = false
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

	data := make([]byte, p.buf.Len())
	if _, err := p.buf.Read(data); err != nil {
		return msg, err
	}

	logp.Info("** packetSize: %d", packetSize)
	logp.Info("** spid: %d", spid)
	logp.Info("** requestType: %s", msg.requestType)
	logp.Info("** data: %s", data)

	// Mark buffer as read (even if it's not)
	p.buf.Advance(p.buf.Len())

	return msg, nil
}
