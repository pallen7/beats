package mssql

import (
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/packetbeat/config"
	"github.com/elastic/beats/v7/packetbeat/protos"
)

type tdsConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = tdsConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)

func (c *tdsConfig) Validate() error {
	logp.Info("config.Validate()")
	return nil
}
