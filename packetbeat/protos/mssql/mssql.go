package mssql

import (
	"sync"
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
)

// mssqlPlugin application level protocol analyzer plugin
type mssqlPlugin struct {
	ports        protos.PortsConfig
	parserConfig parserConfig
	transConfig  transactionConfig
	pub          transPub

	// Due to the long lived nature of SQL connections we need to hold the sqlConnection data that's pertinent to parsing
	// so that it doesn't get cleaned up with the TCP level connection data
	sqlconns map[common.HashableIPPortTuple]*sqlConnection
	sync.RWMutex
}

type sqlConnection struct {
	loginAck                bool
	colEncryptionNegotiated bool
}

// Uni-directional tcp stream state for parsing messages.
type stream struct {
	parser parser
}

// Application Layer tcp stream data to be stored on tcp connection context.
type connection struct {
	streams [2]*stream
	trans   transaction
}

var debugf = logp.MakeDebug("mssql")

func init() {
	protos.Register("mssql", New)
}

// New create and initializes a new mssql protocol analyzer instance.
func New(
	testMode bool,
	results protos.Reporter,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &mssqlPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (tp *mssqlPlugin) init(results protos.Reporter, config *tdsConfig) error {
	if err := tp.setFromConfig(config); err != nil {
		return err
	}
	tp.sqlconns = make(map[common.HashableIPPortTuple]*sqlConnection)
	tp.pub.results = results
	return nil
}

func (tp *mssqlPlugin) setFromConfig(config *tdsConfig) error {
	// set module configuration
	if err := tp.ports.Set(config.Ports); err != nil {
		return err
	}
	parser := &tp.parserConfig
	trans := &tp.transConfig
	pub := &tp.pub

	parser.maxBytes = tcp.TCPMaxDataInStream
	trans.transactionTimeout = config.TransactionTimeout
	pub.sendRequest = config.SendRequest
	pub.sendResponse = config.SendResponse
	return nil
}

// ConnectionTimeout returns the per stream connection timeout.
func (tp *mssqlPlugin) ConnectionTimeout() time.Duration {
	return tp.transConfig.transactionTimeout
}

// GetPorts returns the ports numbers packets shall be processed for.
func (tp *mssqlPlugin) GetPorts() []int {
	return tp.ports.Ports
}

// Parse processes a TCP packet. Return nil if connection
// state shall be dropped (e.g. parser not in sync with tcp stream)
func (tp *mssqlPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("Parse mssqlPlugin exception")

	// Use the pkt tuple as the tcptuple includes the tcp stream id
	ipPortTuple := getHashableTuple(pkt, dir)
	sqlConn, sqlConnFound := tp.lookupSQLConnection(ipPortTuple)

	conn := tp.ensureConnection(private)
	st := conn.streams[dir]

	if st == nil {
		st = &stream{}
		st.parser.init(
			&tp.parserConfig,
			func(msg *message) error {
				return conn.trans.onMessage(tcptuple.IPPort(), dir, msg)
			},
		)
		conn.streams[dir] = st
	}

	// todo: We can live with some parse errors and still want to create a transaction but with limited data (ECS type fields)
	if err := st.parser.feed(pkt.Ts, pkt.Payload, conn.trans.requestType, sqlConn); err != nil {
		debugf("%v, dropping TCP stream for error in direction %v.", err, dir)
		// todo: return nil (after updating the conn if required)
		conn.streams[0] = nil
		conn.streams[1] = nil
		conn.trans.resetData()
	}
	// If a login has been acknowledged and we don't have these connection details then save them
	if !sqlConnFound && sqlConn.loginAck {
		debugf("login acknowledged for: %s (hashable:%v)", pkt.Tuple.String(), ipPortTuple)
		tp.RWMutex.Lock()
		tp.sqlconns[ipPortTuple] = sqlConn
		tp.RWMutex.Unlock()
	}
	return conn
}

func (tp *mssqlPlugin) ReceivedFin(
	tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	return private
}

// GapInStream is called when a gap of nbytes bytes is found in the stream (due to packet loss).
// We need to retain the private connection data so return false
// TODO: Add an error message to our Transaction. Our parser will handle the error for a missing data?
func (tp *mssqlPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int,
	private protos.ProtocolData,
) (protos.ProtocolData, bool) {
	logp.Warn("mssql gap in stream")
	return nil, false
}

func getHashableTuple(pkt *protos.Packet, dir uint8) common.HashableIPPortTuple {
	if dir == tcp.TCPDirectionReverse {
		debugf("reversing pkt tuple")
		return pkt.Tuple.RevHashable()
	}
	return pkt.Tuple.Hashable()
}

func (tp *mssqlPlugin) lookupSQLConnection(ip common.HashableIPPortTuple) (*sqlConnection, bool) {
	tp.RWMutex.RLock()
	conn, found := tp.sqlconns[ip]
	tp.RWMutex.RUnlock()
	if !found {
		debugf("sql connection not found, hashable ipporttuple:(%v)", ip)
		conn = &sqlConnection{}
	}
	return conn, found
}

func (tp *mssqlPlugin) ensureConnection(private protos.ProtocolData) *connection {
	conn := getConnection(private)
	if conn == nil {
		conn = &connection{}
		conn.trans.init(&tp.transConfig, tp.pub.onTransaction)
	}
	return conn
}

func getConnection(private protos.ProtocolData) *connection {
	if private == nil {
		return nil
	}

	priv, ok := private.(*connection)
	if !ok {
		logp.Warn("mssql connection type error")
		return nil
	}
	if priv == nil {
		logp.Warn("Unexpected: mssql connection data not set")
		return nil
	}
	return priv
}
