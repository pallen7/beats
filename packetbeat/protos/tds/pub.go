package tds

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

func (pub *transPub) onTransaction(requ, resp *message) error {
	logp.Info("pub.onTransaction()")
	if pub.results == nil {
		return nil
	}

	pub.results(pub.createEvent(requ, resp))
	return nil
}

func (pub *transPub) createEvent(requ, resp *message) beat.Event {
	logp.Info("pub.createEvent()")

	evt, pbf := pb.NewBeatEvent(requ.Ts)

	// Look at the other packetbeat protos and decide which of the ECS fields to include. mysql.go has straight-forward examples

	pbf.Network.Transport = "tcp"
	fields := evt.Fields
	fields["type"] = "mssql" // Mandatory field

	// We should be creating these sub-request values as we parse
	// mssq.request.*
	mssqlrequest := common.MapStr{
		"request_type": requ.requestType,
	}

	mssqlresponse := common.MapStr{
		"rows_returned": resp.rowsReturned,
	}

	// mssql.event:
	mssql := common.MapStr{
		"request":  mssqlrequest,
		"response": mssqlresponse,
	}

	fields["mssql"] = mssql

	logp.Info("** published event: %v", evt)

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
	// 	"type":         "tds",
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
	// pbf.Event.Dataset = "tds"

	// logp.Info("** pbf.Network: %v", pbf.Network)

	// pbf.Network.Transport = "tcp"
	// pbf.Network.Protocol = pbf.Event.Dataset

	// logp.Info("** event: %v", evt)

	return evt
}
