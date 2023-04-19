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

package main

import (
	"fmt"
	"net"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/share"
	mock_ipamwrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/ipamwrapper/mocks"
	mock_iptables "github.com/aws/amazon-vpc-cni-k8s/pkg/iptableswrapper/mocks"
	mock_netlinkwrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper/mocks"
	mock_nswrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper/mocks"
	mock_procsyswrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper/mocks"
	mock_veth "github.com/aws/amazon-vpc-cni-k8s/pkg/vethwrapper/mocks"
)

const (
	containerIfName = "v6if0"
	hostIfName      = "vethxxxx"
)

func TestCmdAddV6(t *testing.T) {
	ctrl := gomock.NewController(t)

	ipt := mock_iptables.NewMockIptablesIface(ctrl)

	args := &skel.CmdArgs{
		ContainerID: "0eac76975acb3a3b7d6ce694d372314d34ab9107e8e05a7ac4da2054d8aae5eb",
		IfName:      "eth0",
		StdinData: []byte(`{
				"cniVersion":"0.4.0",
				"mtu":"9001",
				"name":"aws-cni",
				"enabled":"true",
				"nodeIP": "2600::",
				"ipam": {"type":"host-local","ranges":[[{"subnet": "fd00::/8"}]],"routes":[{"dst":"::/0"}],"dataDir":"/run/cni/v6pd/egress-v4-ipam"},
				"pluginLogFile":"plugin.log",
				"pluginLogLevel":"DEBUG",
				"podSGEnforcingMode":"strict",
				"prevResult":
					{
					"cniVersion":"0.4.0",
					"interfaces":
						[
							{"name":"eni36e5b0ee702"},
							{"name":"eth0","sandbox":"/var/run/netns/cni-266298c1-b141-9c7f-f26b-97ff084f3fcc"},
							{"name":"dummy36e5b0ee702","mac":"0","sandbox":"0"}],
					"ips":
						[{"version":"4","interface":1,"address":"192.168.13.226/32"}],
					"dns":{}
					},
				"type":"aws-cni",
				"vethPrefix":"eni"
		}`),
	}
	c := &share.Context{
		Procsys:    mock_procsyswrapper.NewMockProcSys(ctrl),
		Ns:         mock_nswrapper.NewMockNS(ctrl),
		NsPath:     "/var/run/netns/cni-xxxx",
		ArgsIfName: args.IfName,
		Ipam:       mock_ipamwrapper.NewMockIpam(ctrl),
		Link:       mock_netlinkwrapper.NewMockNetLink(ctrl),
		Veth:       mock_veth.NewMockVeth(ctrl),
		Iptv6:      ipt,
		Iptv4:      ipt,
		Mtu:        9001,
	}

	err := share.SetupAddExpectV6(*c, &[]string{}, &[]string{}, &[]string{})
	assert.Nil(t, err)

	c.Ipam.(*mock_ipamwrapper.MockIpam).EXPECT().ExecAdd("host-local", gomock.Any()).Return(
		&current.Result{
			CNIVersion: "0.4.0",
			IPs: []*current.IPConfig{
				&current.IPConfig{
					Version: "6",
					Address: net.IPNet{
						IP:   net.ParseIP("fd00:10"),
						Mask: net.CIDRMask(8, 128),
					},
				},
			},
		}, nil)

	c.Iptv6.(*mock_iptables.MockIptablesIface).EXPECT().NewChain("nat", "CNI-E6-298d8b75a8d254672ccd7").Return(nil)

	err = _cmdAdd(args, c)
	assert.Nil(t, err)

	// the unit test write some output string not ends with '\n' and this cause go runner unable to interpret that a test was run.
	// Adding a newline, keeps a clean output
	fmt.Println()
}

func TestCmdDelV6(t *testing.T) {
	ctrl := gomock.NewController(t)

	ipt := mock_iptables.NewMockIptablesIface(ctrl)

	args := &skel.CmdArgs{
		ContainerID: "0eac76975acb3a3b7d6ce694d372314d34ab9107e8e05a7ac4da2054d8aae5eb",
		IfName:      "eth0",
		StdinData: []byte(`{
				"cniVersion":"0.4.0",
				"mtu":"9001",
				"name":"aws-cni",
				"enabled":"true",
				"nodeIP": "2600::",
				"ipam": {"type":"host-local","ranges":[[{"subnet": "fd00::/8"}]],"routes":[{"dst":"::/0"}],"dataDir":"/run/cni/v6pd/egress-v4-ipam"},
				"pluginLogFile":"plugin.log",
				"pluginLogLevel":"DEBUG",
				"podSGEnforcingMode":"strict",
				"prevResult":
					{
					"cniVersion":"0.4.0",
					"interfaces":
						[
							{"name":"eni36e5b0ee702"},
							{"name":"eth0","sandbox":"/var/run/netns/cni-266298c1-b141-9c7f-f26b-97ff084f3fcc"},
							{"name":"dummy36e5b0ee702","mac":"0","sandbox":"0"}],
					"ips":
						[{"version":"4","interface":1,"address":"192.168.13.226/32"}],
					"dns":{}
					},
				"type":"aws-cni",
				"vethPrefix":"eni"
		}`),
	}
	c := &share.Context{
		Procsys:    mock_procsyswrapper.NewMockProcSys(ctrl),
		Ns:         mock_nswrapper.NewMockNS(ctrl),
		NsPath:     "/var/run/netns/cni-xxxx",
		ArgsIfName: args.IfName,
		Ipam:       mock_ipamwrapper.NewMockIpam(ctrl),
		Link:       mock_netlinkwrapper.NewMockNetLink(ctrl),
		Veth:       mock_veth.NewMockVeth(ctrl),
		Iptv6:      ipt,
		Iptv4:      ipt,
		Mtu:        9001,
	}

	err := share.SetupDelExpectV6(*c, &[]string{}, &[]string{})
	assert.Nil(t, err)

	c.Ipam.(*mock_ipamwrapper.MockIpam).EXPECT().ExecDel("host-local", gomock.Any()).Return(nil)

	c.Iptv6.(*mock_iptables.MockIptablesIface).EXPECT().ClearChain("nat", "CNI-E6-298d8b75a8d254672ccd7").Return(nil)
	c.Iptv6.(*mock_iptables.MockIptablesIface).EXPECT().DeleteChain("nat", "CNI-E6-298d8b75a8d254672ccd7").Return(nil)

	err = _cmdDel(args, c)
	assert.Nil(t, err)
}

func TestCmdAddV4(t *testing.T) {
	ctrl := gomock.NewController(t)

	ipt := mock_iptables.NewMockIptablesIface(ctrl)

	args := &skel.CmdArgs{
		ContainerID: "0eac76975acb3a3b7d6ce694d372314d34ab9107e8e05a7ac4da2054d8aae5eb",
		IfName:      "eth0",
		StdinData: []byte(`{
				"cniVersion":"0.4.0",
				"mtu":"9001",
				"name":"aws-cni",
				"enabled":"true",
				"nodeIP": "192.168.1.123",
				"ipam": {"type":"host-local","ranges":[[{"subnet": "169.254.172.0/22"}]],"routes":[{"dst":"0.0.0.0"}],"dataDir":"/run/cni/v6pd/egress-v4-ipam"},
				"pluginLogFile":"plugin.log",
				"pluginLogLevel":"DEBUG",
				"podSGEnforcingMode":"strict",
				"prevResult":
					{
					"cniVersion":"0.4.0",
					"interfaces":
						[
							{"name":"eni36e5b0ee702"},
							{"name":"eth0","sandbox":"/var/run/netns/cni-266298c1-b141-9c7f-f26b-97ff084f3fcc"},
							{"name":"dummy36e5b0ee702","mac":"0","sandbox":"0"}],
					"ips":
						[{"version":"4","interface":1,"address":"192.168.13.226/32"}],
					"dns":{}
					},
				"type":"aws-cni",
				"vethPrefix":"eni"
		}`),
	}
	c := &share.Context{
		Procsys:    mock_procsyswrapper.NewMockProcSys(ctrl),
		Ns:         mock_nswrapper.NewMockNS(ctrl),
		NsPath:     "/var/run/netns/cni-xxxx",
		ArgsIfName: args.IfName,
		Ipam:       mock_ipamwrapper.NewMockIpam(ctrl),
		Link:       mock_netlinkwrapper.NewMockNetLink(ctrl),
		Veth:       mock_veth.NewMockVeth(ctrl),
		Iptv6:      ipt,
		Iptv4:      ipt,
		Mtu:        9001,
	}

	err := share.SetupAddExpectV4(*c, &[]string{}, &[]string{}, &[]string{})
	assert.Nil(t, err)

	c.Ipam.(*mock_ipamwrapper.MockIpam).EXPECT().ExecAdd("host-local", gomock.Any()).Return(
		&current.Result{
			CNIVersion: "0.4.0",
			IPs: []*current.IPConfig{
				&current.IPConfig{
					Version: "4",
					Address: net.IPNet{
						IP:   net.ParseIP("169.254.172.10"),
						Mask: net.CIDRMask(22, 32),
					},
				},
			},
		}, nil)

	c.Iptv6.(*mock_iptables.MockIptablesIface).EXPECT().NewChain("nat", "CNI-E4-298d8b75a8d254672ccd7").Return(nil)

	err = _cmdAdd(args, c)
	assert.Nil(t, err)

	// the unit test write some output string not ends with '\n' and this cause go runner unable to interpret that a test was run.
	// Adding a newline, keeps a clean output
	fmt.Println()
}

func TestCmdDelV4(t *testing.T) {
	ctrl := gomock.NewController(t)

	ipt := mock_iptables.NewMockIptablesIface(ctrl)

	args := &skel.CmdArgs{
		ContainerID: "0eac76975acb3a3b7d6ce694d372314d34ab9107e8e05a7ac4da2054d8aae5eb",
		IfName:      "eth0",
		StdinData: []byte(`{
				"cniVersion":"0.4.0",
				"mtu":"9001",
				"name":"aws-cni",
				"enabled":"true",
				"nodeIP": "192.168.1.123",
				"ipam": {"type":"host-local","ranges":[[{"subnet": "fd00::/8"}]],"routes":[{"dst":"::/0"}],"dataDir":"/run/cni/v6pd/egress-v4-ipam"},
				"pluginLogFile":"plugin.log",
				"pluginLogLevel":"DEBUG",
				"podSGEnforcingMode":"strict",
				"prevResult":
					{
					"cniVersion":"0.4.0",
					"interfaces":
						[
							{"name":"eni36e5b0ee702"},
							{"name":"eth0","sandbox":"/var/run/netns/cni-266298c1-b141-9c7f-f26b-97ff084f3fcc"},
							{"name":"dummy36e5b0ee702","mac":"0","sandbox":"0"}],
					"ips":
						[{"version":"4","interface":1,"address":"192.168.13.226/32"}],
					"dns":{}
					},
				"type":"aws-cni",
				"vethPrefix":"eni"
		}`),
	}
	c := &share.Context{
		Procsys:    mock_procsyswrapper.NewMockProcSys(ctrl),
		Ns:         mock_nswrapper.NewMockNS(ctrl),
		NsPath:     "/var/run/netns/cni-xxxx",
		ArgsIfName: args.IfName,
		Ipam:       mock_ipamwrapper.NewMockIpam(ctrl),
		Link:       mock_netlinkwrapper.NewMockNetLink(ctrl),
		Veth:       mock_veth.NewMockVeth(ctrl),
		Iptv6:      ipt,
		Iptv4:      ipt,
		Mtu:        9001,
	}

	err := share.SetupDelExpectV4(*c, &[]string{}, &[]string{})
	assert.Nil(t, err)

	c.Ipam.(*mock_ipamwrapper.MockIpam).EXPECT().ExecDel("host-local", gomock.Any()).Return(nil)

	c.Iptv6.(*mock_iptables.MockIptablesIface).EXPECT().ClearChain("nat", "CNI-E4-298d8b75a8d254672ccd7").Return(nil)
	c.Iptv6.(*mock_iptables.MockIptablesIface).EXPECT().DeleteChain("nat", "CNI-E4-298d8b75a8d254672ccd7").Return(nil)

	err = _cmdDel(args, c)
	assert.Nil(t, err)
}
