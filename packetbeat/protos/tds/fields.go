// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Code generated by beats/dev-tools/cmd/asset/asset.go - DO NOT EDIT.

package tds

import (
	"github.com/elastic/beats/v7/libbeat/asset"
)

func init() {
	if err := asset.SetFields("packetbeat", "tds", asset.ModuleFieldsPri, AssetTds); err != nil {
		panic(err)
	}
}

// AssetTds returns asset data.
// This is the base64 encoded gzipped contents of protos/tds.
func AssetTds() string {
	return "eJxsjjHSgkAMhfs9xRuq/y/gAFtYUWKBuxdw4KEZEVY2OLO3d0RwKHxVJsn3JTluTBbaRgOoaE+LzJcuM0DL2EwSVMbB4mAAwJcOf0fn6uo/j4GNdNKATw6KTti3sTBYK7sAOYbznduBdzQFWlymcQ5rZ7+/ZyY+Zkb1KfA7+/nVFn/losfYwdUVTh9BYV4BAAD//5jxQKM="
}
