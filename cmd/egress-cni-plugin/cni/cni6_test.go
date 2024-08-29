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

func TestCmdAddEgressV6(t *testing.T) {
	context := setupAddContextV6(gomock.NewController(t))

	expectIptablesRules := []string{
		"nat CNI-E6 -d ff00::/8 -j ACCEPT -m comment --comment unit-test-comment",
		"nat CNI-E6 -j SNAT --to-source 2600:: -m comment --comment unit-test-comment --random-fully",
		"nat POSTROUTING -s fd00::10 -j CNI-E6 -m comment --comment unit-test-comment",
	}
	actualIptablesRules := []string{}

	expectRouteAdd := []string{
		"{Ifindex: 100 Dst: fd00::10/128 Src: <nil> Gw: <nil> Flags: [] Table: 0}",
	}
	actualRouteAdd := []string{}

	expectRouteReplace := []string{"{Ifindex: 2 Dst: ::/0 Src: <nil> Gw: fe80::10 Flags: [] Table: 0}"}
	actualRouteReplace := []string{}

	SetupAddExpectV6(context, &actualIptablesRules, &actualRouteAdd, &actualRouteReplace)

	err := CmdAddEgressV6(&context)
	assert.Nil(t, err)

	assert.EqualValuesf(t, expectIptablesRules, actualIptablesRules, "iptables chain and rules are added")

	assert.EqualValuesf(t, expectRouteReplace, actualRouteReplace, "route replaced in container and host")

	assert.EqualValuesf(t, expectRouteAdd, actualRouteAdd, "route added in container and host")

	// the unit test write some output string not ends with '\n' and this cause go runner unable to interpret that a test was run.
	// Adding a newline, keeps a clean output
	fmt.Println()

}

func TestCmdDelEgressV6(t *testing.T) {
	context := setupDelContextV6(gomock.NewController(t))

	expectLinkDel := []string{"link del - name: v6if0"}
	actualLinkDel := []string{}

	expectIptablesDel := []string{
		"nat POSTROUTING -s fd00::10 -j CNI-E6 -m comment --comment unit-test-comment",
		"clear chain nat CNI-E6",
		"del chain nat CNI-E6"}
	actualIptablesDel := []string{}
	SetupDelExpectV6(context, &actualLinkDel, &actualIptablesDel)

	err := CmdDelEgressV6(&context)
	assert.Nil(t, err)

	assert.EqualValuesf(t, expectIptablesDel, actualIptablesDel, "iptables chain and rules should be removed")

	assert.EqualValuesf(t, expectLinkDel, actualLinkDel, "link should be removed in container")
}

func setupAddContextV6(ctrl *gomock.Controller) Context {
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
			NodeIP:         net.ParseIP("2600::"),
			IfName:         EgressIPv6InterfaceName,
			MTU:            "9001",
			PluginLogFile:  "plugin.log",
			PluginLogLevel: "DEBUG",
		},
		Log: logger.New(&logger.Configuration{
			LogLevel:    "DEBUG",
			LogLocation: "plugin.log",
		}),
		Iptv6:      ipt,
		Iptv4:      ipt,
		Chain:      "CNI-E6",
		Comment:    "unit-test-comment",
		ArgsIfName: "eth0",

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
					Version: "4",
					Address: net.IPNet{
						IP:   net.ParseIP("192.168.1.100"),
						Mask: net.CIDRMask(24, 32),
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
					Version: "6",
					Address: net.IPNet{
						IP:   net.ParseIP("fd00::10"),
						Mask: net.CIDRMask(8, 128),
					},
					Gateway: net.ParseIP("fd00::1"),
				},
			},
		},
	}
}

func setupDelContextV6(ctrl *gomock.Controller) Context {
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
			NodeIP:         net.ParseIP("2600::"),
			IfName:         EgressIPv6InterfaceName,
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
		Chain:   "CNI-E6",
		Comment: "unit-test-comment",
	}
}
