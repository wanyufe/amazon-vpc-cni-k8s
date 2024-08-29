// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package share

import (
	"github.com/containernetworking/cni/pkg/types/current"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/ipamwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/iptableswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/logger"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/vethwrapper"
)

// Context includes all info to run container ADD/DEL action
type Context struct {
	Procsys    procsyswrapper.ProcSys
	Ipam       ipamwrapper.Ipam
	Link       netlinkwrapper.NetLink
	Ns         nswrapper.NS
	NsPath     string
	ArgsIfName string
	Veth       vethwrapper.Veth
	Iptv4      iptableswrapper.IptablesIface
	Iptv6      iptableswrapper.IptablesIface

	NetConf   *NetConf
	Result    *current.Result
	TmpResult *current.Result
	Log       logger.Logger

	Mtu     int
	Chain   string
	Comment string
}
