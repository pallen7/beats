package mssql

import (
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"

	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/protos"
)

// Transaction Publisher.
type transPub struct {
	sendRequest  bool
	sendResponse bool

	results protos.Reporter
}

func (pub *transPub) onTransaction(tran *transaction) error {
	logp.Info("pub.onTransaction()")
	if pub.results == nil {
		return nil
	}

	pub.results(pub.createEvent(tran))
	return nil
}

type table struct {
	rowcount int
}

func (pub *transPub) createEvent(tran *transaction) beat.Event {
	logp.Info("pub.createEvent()")

	// todo: if we have no request type we should not create an event - not sure where this should live

	evt, _ := pb.NewBeatEvent(tran.Ts.Ts)

	// Create our SQL specific fields here
	tran.Event(&evt)

	fields := evt.Fields

	mssqlrequest := common.MapStr{
		"request_type": getRequestTypeString(tran.requestType),
	}

	// Fairly arbitrary truncation:
	// todo: only output sql_batch for the SQL batch request type
	if len(tran.sqlBatch) > 500 {
		mssqlrequest["sql_batch"] = tran.sqlBatch[0:497] + "..."
	} else {
		mssqlrequest["sql_batch"] = tran.sqlBatch
	}

	mssqlrequest["proc_name"] = tran.procName

	mssqlresponse := common.MapStr{
		"rows_returned": tran.rowsReturned,
		"result_sets":   tran.resultSets,
	}

	// mssql.event:
	mssql := common.MapStr{
		"request": mssqlrequest,
	}

	// todo: Need a better way to coordinate this. Only log responses for request types that we process
	if tran.requestType == rpcMessage || tran.requestType == sqlBatchMessage {
		mssql["response"] = mssqlresponse
	}

	fields["mssql"] = mssql

	logp.Info("** published event: %v", evt)

	// Look at the other packetbeat protos and decide which of the ECS fields to include. mysql.go has straight-forward examples

	// //pbf.Network.Transport = "tcp"
	// fields := evt.Fields
	// fields["type"] = "mssql" // Mandatory field (already added?)

	// Code below here predominantly comes from the template - have a review

	// status := common.OK_STATUS

	// // resp_time in milliseconds
	// responseTime := int32(resp.Ts.Sub(requ.Ts).Nanoseconds() / 1e6)

	// src := &common.Endpoint{
	// 	IP:      requ.Tuple.SrcIP.String(),
	// 	Port:    requ.Tuple.SrcPort,
	// 	Process: requ.CmdlineTuple.Src,
	// }
	// dst := &common.Endpoint{
	// 	IP:      requ.Tuple.DstIP.String(),
	// 	Port:    requ.Tuple.DstPort,
	// 	Process: requ.CmdlineTuple.Dst,
	// }

	// fields := common.MapStr{
	// 	"type":         "mssql",
	// 	"status":       status,
	// 	"responsetime": responseTime,
	// 	// "bytes_in":     requ.Size,
	// 	// "bytes_out":    resp.Size,
	// 	"src":          src,
	// 	"dst":          dst,
	// 	"mssql.requestType": requ.requestType,
	// }

	// // add processing notes/errors to event
	// if len(requ.Notes)+len(resp.Notes) > 0 {
	// 	fields["notes"] = append(requ.Notes, resp.Notes...)
	// }

	// if pub.sendRequest {
	// 	// fields["request"] =
	// }
	// if pub.sendResponse {
	// 	// fields["response"] =
	// }

	// // pbf (packetbeat fields) - contains (some of) the packetbeat ecs fields

	// pbf.SetSource(src)
	// pbf.SetDestination(dst)
	// evt.Fields = fields
	// pbf.Event.Dataset = "mssql"

	// logp.Info("** pbf.Network: %v", pbf.Network)

	// pbf.Network.Transport = "tcp"
	// pbf.Network.Protocol = pbf.Event.Dataset

	// logp.Info("** event: %v", evt)

	return evt
}

func getRequestTypeString(messageType byte) string {
	switch messageType {
	case attentionSignalMessage:
		return "Attention Signal"
	case bulkLoadDataMessage:
		return "Bulk load data"
	case federatedAuthenticationTokenMesage:
		return "Federated Authentication Token"
	case preLoginMessage:
		return "Pre-Login"
	case preTds7LoginMessage:
		return "Pre-TDS7 Login"
	case rpcMessage:
		return "RPC"
	case sspiMessage:
		return "SSPI"
	case sqlBatchMessage:
		return "SQL Batch"
	case tds7LoginMessage:
		return "TDS7 Login"
	case transactionManagerRequestMessage:
		return "Transaction Manager Request"
	}
	return "Unknown"
}

/*
Experimentation:

The below worked to produce nested objects but not sure how much value we get out of the granular breakdown of each result. It is
possible to aggregate on the nested elements but doesn't seem to add much value?

	mapColumna1 := common.MapStr{"name": "id", "type": "int"}
	mapColumna2 := common.MapStr{"name": "address", "type": "varchar(20)"}

	mapColumnb1 := common.MapStr{"name": "sno", "type": "bigint"}

	mapColumnsa := make([]common.MapStr, 2)
	mapColumnsb := make([]common.MapStr, 1)

	mapColumnsa[0] = mapColumna1
	mapColumnsa[1] = mapColumna2
	mapColumnsb[0] = mapColumnb1

	mapTables := make([]common.MapStr, 2)
	mapTables[0] = common.MapStr{"rows_returned": 10, "columns": mapColumnsa}
	mapTables[1] = common.MapStr{"rows_returned": 20, "columns": mapColumnsb}

	Produced in Elastic/Kibana:
	{
	"rows_returned": 10,
	"columns": [
		{
		"name": "id",
		"type": "int"
		},
		{
		"name": "address",
		"type": "varchar(20)"
		}
	]
	},
	{
	"rows_returned": 20,
	"columns": [
		{
		"type": "bigint",
		"name": "sno"
		}
	]
	}

*/
