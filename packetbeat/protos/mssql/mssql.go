package mssql

import (
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
}

// Application Layer tcp stream data to be stored on tcp connection context.
type connection struct {
	streams [2]*stream
	trans   mssqlTransaction
}

// Uni-directional tcp stream state for parsing messages.
type stream struct {
	parser parser
}

var (
	debugf = logp.MakeDebug("mssql")

	// use isDebug/isDetailed to guard debugf/detailedf to minimize allocations
	// (garbage collection) when debug log is disabled.
	isDebug = true
)

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
	tp.pub.results = results

	isDebug = logp.IsDebug("http")
	return nil
}

func (tp *mssqlPlugin) setFromConfig(config *tdsConfig) error {

	// set module configuration
	if err := tp.ports.Set(config.Ports); err != nil {
		return err
	}

	// set parser configuration
	parser := &tp.parserConfig
	parser.maxBytes = tcp.TCPMaxDataInStream

	// set transaction correlator configuration
	trans := &tp.transConfig
	trans.transactionTimeout = config.TransactionTimeout

	// set transaction publisher configuration
	pub := &tp.pub
	pub.sendRequest = config.SendRequest
	pub.sendResponse = config.SendResponse

	return nil
}

// ConnectionTimeout returns the per stream connection timeout.
// Return <=0 to set default tcp module transaction timeout.
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

	conn := tp.ensureConnection(private)
	st := conn.streams[dir]
	if st == nil {
		st = &stream{}
		st.parser.init(&tp.parserConfig, func(msg *message) error {
			return conn.trans.onMessage(tcptuple.IPPort(), dir, msg)
		})
		conn.streams[dir] = st
	}

	if err := st.parser.feed(pkt.Ts, pkt.Payload); err != nil {
		debugf("%v, dropping TCP stream for error in direction %v.", err, dir)
		tp.onDropConnection(conn) // todo: we can remove this if we aren't going to do anything with errors that are returned
		return nil
	}
	return conn
}

// ReceivedFin handles TCP-FIN packet.
func (tp *mssqlPlugin) ReceivedFin(
	tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	return private
}

// GapInStream handles lost packets in tcp-stream.
func (tp *mssqlPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int,
	private protos.ProtocolData,
) (protos.ProtocolData, bool) {
	conn := getConnection(private)
	if conn != nil {
		tp.onDropConnection(conn)
	}

	return nil, true
}

// onDropConnection processes and optionally sends incomplete
// transaction in case of connection being dropped due to error
func (tp *mssqlPlugin) onDropConnection(conn *connection) {

}

func (tp *mssqlPlugin) ensureConnection(private protos.ProtocolData) *connection {
	conn := getConnection(private)
	if conn == nil {
		conn = &connection{}
		conn.trans.init(&tp.transConfig, tp.pub.onTransaction)
	}
	return conn
}

func (conn *connection) dropStreams() {
	conn.streams[0] = nil
	conn.streams[1] = nil
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
