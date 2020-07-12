package mssql

import (
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
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

// todo: remove
func (trans *transaction) resetData() {
	trans.Transaction = applayer.Transaction{}
	trans.mssqlFields = mssqlFields{}
}

func (trans *transaction) init(c *transactionConfig, cb transactionHandler) {
	trans.config = c
	trans.onTransaction = cb
}

func (trans *transaction) onMessage(
	tuple *common.IPPortTuple,
	dir uint8,
	msg *message,
) error {
	var err error

	msg.Tuple = *tuple
	msg.Transport = applayer.TransportTCP
	msg.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(&msg.Tuple, msg.Transport)

	if msg.IsRequest {
		err = trans.onRequest(tuple, dir, msg)
	} else {
		err = trans.onResponse(tuple, dir, msg)
		trans.resetData()
	}

	return err
}

func (trans *transaction) onRequest(
	tuple *common.IPPortTuple,
	dir uint8,
	msg *message,
) error {
	trans.InitWithMsg("mssql", &msg.Message)
	trans.BytesIn = msg.header.totalBytes
	trans.requestType = msg.header.messageType
	trans.sqlBatch = msg.sqlBatch
	trans.procName = msg.procName
	return nil
}

func (trans *transaction) onResponse(
	tuple *common.IPPortTuple,
	dir uint8,
	msg *message,
) error {
	trans.EndTime = msg.Ts
	trans.Status = common.OK_STATUS
	trans.BytesOut = msg.header.totalBytes
	trans.rowsReturned = msg.rowsReturned
	trans.resultSets = msg.resultSets

	if err := trans.onTransaction(trans); err != nil {
		return err
	}
	return nil
}
