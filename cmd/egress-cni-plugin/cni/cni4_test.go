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

package cni

import (
	"fmt"
	"net"
	"testing"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/stretchr/testify/assert"

	. "github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/share"
	mock_iptables "github.com/aws/amazon-vpc-cni-k8s/pkg/iptableswrapper/mocks"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/logger"

	mock_netlinkwrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper/mocks"

	mock_nswrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper/mocks"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"

	mock_ipamwrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/ipamwrapper/mocks"
	mock_procsyswrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper/mocks"
	mock_veth "github.com/aws/amazon-vpc-cni-k8s/pkg/vethwrapper/mocks"
)

func TestCmdAddEgressV4(t *testing.T) {
	context := setupAddContextV4(gomock.NewController(t))

	expectIptablesRules := []string{
		"nat CNI-E4 -d 224.0.0.0/4 -j ACCEPT -m comment --comment unit-test-comment",
		"nat CNI-E4 -j SNAT --to-source 192.168.0.23 -m comment --comment unit-test-comment --random-fully",
		"nat POSTROUTING -s 169.254.172.100 -j CNI-E4 -m comment --comment unit-test-comment"}
	var actualIptablesRules []string

	expectRouteDel := []string{"route del: {Ifindex: 2 Dst: 169.254.172.0/22 Src: <nil> Gw: <nil> Flags: [] Table: 0}"}
	var actualRouteDel []string

	expectRouteAdd := []string{
		"route add: {Ifindex: 2 Dst: 169.254.172.1/32 Src: 169.254.172.100 Gw: <nil> Flags: [] Table: 0}",
		"route add: {Ifindex: 2 Dst: 169.254.172.0/22 Src: 169.254.172.100 Gw: 169.254.172.1 Flags: [] Table: 0}",
		"route add: {Ifindex: 100 Dst: 169.254.172.100/32 Src: <nil> Gw: <nil> Flags: [] Table: 0}"}
	var actualRouteAdd []string

	// setup the mock EXPECT
	err := SetupAddExpectV4(context, &actualIptablesRules, &actualRouteAdd, &actualRouteDel)
	assert.Nil(t, err)

	// run egress plugin ADD action
	err = CmdAddEgressV4(&context)
	assert.Nil(t, err)

	// confirm all iptables chain/rule are created
	assert.EqualValuesf(t, expectIptablesRules, actualIptablesRules, "expected iptables chain/rule are not created")

	// confirm automatically added route is removed
	assert.EqualValuesf(t, expectRouteDel, actualRouteDel, "route are expected to removed")

	// confirm routes are added in container and node
	assert.EqualValuesf(t, expectRouteAdd, actualRouteAdd, "route are expected to added")

	// the unit test write some output string not ends with '\n' and this cause go runner unable to interpret that a test was run.
	// Adding a newline, keeps a clean output
	fmt.Println()

}

func TestCmdDelEgressV4(t *testing.T) {
	context := setupDelContextV4(gomock.NewController(t))

	expectLinkDel := []string{"link del - name: v4if0"}
	actualLinkDel := []string{}

	expectIptablesDel := []string{
		"nat POSTROUTING -s 169.254.172.100 -j CNI-E4 -m comment --comment unit-test-comment",
		"clear chain nat CNI-E4",
		"del chain nat CNI-E4"}
	actualIptablesDel := []string{}

	// run egress plugin DEL action
	err := SetupDelExpectV4(context, &actualLinkDel, &actualIptablesDel)
	assert.Nil(t, err)

	err = CmdDelEgressV4(&context)
	assert.Nil(t, err)

	// confirm added interface is removed
	assert.EqualValuesf(t, expectLinkDel, actualLinkDel, "interface are expected to deleted")

	// confirm iptables chain/rules are deleted
	assert.EqualValuesf(t, expectIptablesDel, actualIptablesDel, "iptables chain/rules are expected to deleted")
}

func setupAddContextV4(ctrl *gomock.Controller) Context {
	ipt := mock_iptables.NewMockIptablesIface(ctrl)
	return Context{
		Procsys: mock_procsyswrapper.NewMockProcSys(ctrl),
		Ns:      mock_nswrapper.NewMockNS(ctrl),
		NsPath:  "/var/run/netns/cni-xxxx",
		Ipam:    mock_ipamwrapper.NewMockIpam(ctrl),
		Link:    mock_netlinkwrapper.NewMockNetLink(ctrl),
		Veth:    mock_veth.NewMockVeth(ctrl),
		NetConf: &NetConf{
			NetConf: types.NetConf{
				CNIVersion: "0.4.0",
			},
			NodeIP:         net.ParseIP("192.168.0.23"),
			IfName:         EgressIPv4InterfaceName,
			MTU:            "9001",
			PluginLogFile:  "plugin.log",
			PluginLogLevel: "DEBUG",
		},
		Log: logger.New(&logger.Configuration{
			LogLevel:    "DEBUG",
			LogLocation: "plugin.log",
		}),
		Iptv6:   ipt,
		Iptv4:   ipt,
		Chain:   "CNI-E4",
		Comment: "unit-test-comment",

		Result: &current.Result{
			CNIVersion: "0.4.0",
			Interfaces: []*current.Interface{
				{
					Name: "eni3a52ce78095",
				},
				{
					Name:    "eth0",
					Sandbox: "/var/run/netns/testing",
				},
			},
			IPs: []*current.IPConfig{
				{
					Version: "6",
					Address: net.IPNet{
						IP:   net.ParseIP("2600:1f16:35a:5701:e1:830b:1feb:5f13"),
						Mask: net.CIDRMask(64, 128),
					},
					Interface: current.Int(1),
				},
			},
		},
		TmpResult: &current.Result{
			CNIVersion: "0.4.0",
			Interfaces: nil,
			IPs: []*current.IPConfig{
				{
					Version: "4",
					Address: net.IPNet{
						IP:   net.ParseIP("169.254.172.100"),
						Mask: net.CIDRMask(22, 32),
					},
					Gateway: net.ParseIP("169.254.172.1"),
				},
			},
		},
	}
}

func setupDelContextV4(ctrl *gomock.Controller) Context {
	ipt := mock_iptables.NewMockIptablesIface(ctrl)

	return Context{
		Procsys: mock_procsyswrapper.NewMockProcSys(ctrl),
		Ns:      mock_nswrapper.NewMockNS(ctrl),
		NsPath:  "/var/run/netns/cni-xxxx",
		Ipam:    mock_ipamwrapper.NewMockIpam(ctrl),
		Link:    mock_netlinkwrapper.NewMockNetLink(ctrl),
		Veth:    mock_veth.NewMockVeth(ctrl),
		NetConf: &NetConf{
			NetConf: types.NetConf{
				CNIVersion: "0.4.0",
			},
			NodeIP:         net.ParseIP("192.168.0.23"),
			IfName:         EgressIPv4InterfaceName,
			MTU:            "9001",
			PluginLogFile:  "plugin.log",
			PluginLogLevel: "DEBUG",
		},
		Log: logger.New(&logger.Configuration{
			LogLevel:    "DEBUG",
			LogLocation: "plugin.log",
		}),
		Iptv6:   ipt,
		Iptv4:   ipt,
		Chain:   "CNI-E4",
		Comment: "unit-test-comment",
	}
}
