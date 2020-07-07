package mssql

import (
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos/applayer"
)

type mssqlFields struct {
	// SQL Specific fields
	requestType  byte
	rowsReturned int
	resultSets   int
	sqlBatch     string
	procName     string
}

// A transaction represents a full suite of packets that make up 1 request message & response message
type transaction struct {
	config *transactionConfig

	mssqlFields
	applayer.Transaction

	onTransaction transactionHandler
}

type transactionConfig struct {
	transactionTimeout time.Duration
}

type transactionHandler func(*transaction) error

func (trans *transaction) resetData() {
	trans.Transaction = applayer.Transaction{}
	trans.mssqlFields = mssqlFields{}
}

func (trans *transaction) init(c *transactionConfig, cb transactionHandler) {
	logp.Info("trans.init()")
	trans.config = c
	trans.onTransaction = cb
}

func (trans *transaction) onMessage(
	tuple *common.IPPortTuple,
	dir uint8,
	msg *message,
) error {
	var err error

	// Todo: At this point we need to copy everything from our completed message into our Transaction before the message is cleared

	msg.Tuple = *tuple
	msg.Transport = applayer.TransportTCP
	msg.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(&msg.Tuple, msg.Transport)

	if msg.IsRequest {
		debugf("Received request with tuple: %s", tuple)
		err = trans.onRequest(tuple, dir, msg)
	} else {
		debugf("Received response with tuple: %s", tuple)
		err = trans.onResponse(tuple, dir, msg)
		trans.resetData()
	}

	return err
}

// onRequest handles request messages, merging with incomplete requests
// and adding non-merged requests into the correlation list.
func (trans *transaction) onRequest(
	tuple *common.IPPortTuple,
	dir uint8,
	msg *message,
) error {
	// todo: Create our Transaction information based on the request message

	// If request already exists then (log an error and?) replace the request

	trans.InitWithMsg("mssql", &msg.Message)
	trans.requestType = msg.header.messageType
	trans.sqlBatch = msg.sqlBatch
	trans.procName = msg.procName
	return nil
}

// onRequest handles response messages, merging with incomplete requests
// and adding non-merged responses into the correlation list.
func (trans *transaction) onResponse(
	tuple *common.IPPortTuple,
	dir uint8,
	msg *message,
) error {

	// todo: Add our information into Transaction (i.e. end time, bytes in etc)
	// todo: Check that we have a request on the transaction. If we don't then return an error and dump this response

	trans.rowsReturned = msg.rowsReturned
	trans.resultSets = msg.resultSets

	// todo: Sort this out as it looks a bit weird calling a function on the trans variable and also passing that as a parameter
	if err := trans.onTransaction(trans); err != nil {
		return err
	}
	return nil
}
