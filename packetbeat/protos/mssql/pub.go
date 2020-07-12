package mssql

import (
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"

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
	if pub.results == nil {
		return nil
	}

	if tran.requestType != sqlBatchMessage && tran.requestType != rpcMessage {
		return nil
	}

	pub.results(pub.createEvent(tran))
	return nil
}

type table struct {
	rowcount int
}

func (pub *transPub) createEvent(tran *transaction) beat.Event {

	evt, _ := pb.NewBeatEvent(tran.Ts.Ts)
	tran.Event(&evt)
	fields := evt.Fields

	// Add in SQL specific fields:
	mssqlrequest := common.MapStr{
		"request_type": getRequestTypeString(tran.requestType),
	}
	if tran.requestType == sqlBatchMessage {
		if len(tran.sqlBatch) > 500 {
			mssqlrequest["sql_batch"] = tran.sqlBatch[0:497] + "..."
		} else {
			mssqlrequest["sql_batch"] = tran.sqlBatch
		}
	}
	if tran.requestType == rpcMessage {
		mssqlrequest["proc_name"] = tran.procName
	}
	mssql := common.MapStr{
		"request": mssqlrequest,
	}

	mssqlresponse := common.MapStr{
		"rows_returned": tran.rowsReturned,
		"result_sets":   tran.resultSets,
	}
	mssql["response"] = mssqlresponse

	fields["mssql"] = mssql

	/* todo:
	The docs say raw request / response: https://www.elastic.co/guide/en/beats/packetbeat/current/common-protocol-options.html
	- For a request should we use this to control the SQL Batch that we transmit?
	- For a response do we want to parse out all of the row data? Or send the raw bytes?
	I would have thought neither of these uses makes sense but need confirmation

	if pub.sendResponse {
	}

	if pub.sendRequest {
	}
	*/

	// // add processing notes/errors to event
	// if len(requ.Notes)+len(resp.Notes) > 0 {
	// 	fields["notes"] = append(requ.Notes, resp.Notes...)
	// }
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
Possibly use the below for nested result sets (?)

- columns in result sets
- Params in RPC calls

The below worked to produce nested objects but not sure how much value we get out of the granular breakdown of each result. It is
possible to aggregate on the nested elements but not sure of the value?

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
