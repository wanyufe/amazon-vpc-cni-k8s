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
	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/share"
	"net"
	"testing"

	"github.com/vishvananda/netlink"

	mock_netlinkwrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper/mocks"

	mock_nswrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper/mocks"

	mock_ipamwrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/ipamwrapper/mocks"
	mock_networkutils "github.com/aws/amazon-vpc-cni-k8s/pkg/networkutils/mocks"
	mock_procsyswrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper/mocks"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/logger"
	mock_veth "github.com/aws/amazon-vpc-cni-k8s/pkg/vethwrapper/mocks"
	"github.com/containernetworking/cni/pkg/types/current"
	_ns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestCmdAddEgressV4(t *testing.T) {
	ctrl := gomock.NewController(t)
	ns := mock_nswrapper.NewMockNS(ctrl)
	nsParent, err := _ns.GetCurrentNS() // mock_nswrapper.NewMockNS(ctrl)
	assert.NoError(t, err)

	ipt := mock_networkutils.NewMockIptablesIface(ctrl)
	ipam := mock_ipamwrapper.NewMockIpam(ctrl)
	link := mock_netlinkwrapper.NewMockNetLink(ctrl)
	veth := mock_veth.NewMockVeth(ctrl)
	netConf := &share.NetConf{
		NodeIP:         net.ParseIP("192.168.0.23"),
		IfName:         "v4if0",
		PluginLogFile:  "plugin.log",
		PluginLogLevel: "DEBUG",
	}
	netConf.CNIVersion = "0.4.0"

	log := logger.New(&logger.Configuration{
		LogLevel:    netConf.PluginLogLevel,
		LogLocation: netConf.PluginLogFile,
	})

	procSys := mock_procsyswrapper.NewMockProcSys(ctrl)

	result := &current.Result{
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
	}
	tmpResult := &current.Result{
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
	}
	mtu := 9001
	chain := "CNI-E6"
	comment := "unit-test-comment"
	nsPath := "/var/run/netns/cni-xxxx"
	macHost := [6]byte{0xCB, 0xB8, 0x33, 0x4C, 0x88, 0x4F}
	macCont := [6]byte{0xCC, 0xB8, 0x33, 0x4C, 0x88, 0x4F}

	//	ipam.EXPECT().ExecAdd("local-host", gomock.Any()).Return(tmpResult, nil)
	//&current.Result{
	//	CNIVersion: "0.4.0",
	//	Interfaces: nil,
	//	IPs: []*current.IPConfig{
	//		{
	//			Version: "4",
	//			Address: net.IPNet{
	//				IP:   net.ParseIP("169.254.172.100"),
	//				Mask: net.CIDRMask(22, 32),
	//			},
	//			Gateway: net.ParseIP("169.254.172.1"),
	//		},
	//	},
	//}, nil)

	ns.EXPECT().WithNetNSPath(nsPath, gomock.Any()).Do(func(_nsPath string, f func(_ns.NetNS) error) {
		f(nsParent)
	}).Return(nil)

	veth.EXPECT().Setup(netConf.IfName, mtu, gomock.Any()).Return(
		net.Interface{
			Name:         "vethxxxx",
			HardwareAddr: macHost[:],
		},
		net.Interface{
			Name:         "v4if0",
			HardwareAddr: macCont[:],
		},
		nil)

	link.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Return(nil)
	link.EXPECT().RouteAdd(gomock.Any()).Return(nil)

	link.EXPECT().LinkByName("vethxxxx").Return(
		&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "vethxxxx",
				Index: 100,
			},
		}, nil)
	link.EXPECT().LinkByName("v4if0").Return(
		&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "v4if0",
				Index: 2,
			},
		}, nil)
	link.EXPECT().RouteDel(gomock.Any()).Do(func(arg1 interface{}) error {
		r := arg1.(*netlink.Route)
		expectedResult := &net.IPNet{
			IP:   net.ParseIP("169.254.172.0"),
			Mask: net.CIDRMask(22, 32),
		}
		assert.EqualValuesf(t, expectedResult.String(), r.Dst.String(), "expect route %s needs to be removed, received route %s", expectedResult.String(), r.Dst.String())
		return nil
	}).Return(nil)

	link.EXPECT().RouteAdd(gomock.Any()).Do(func(arg1 interface{}) error {
		r := arg1.(*netlink.Route)
		// container route adding
		if r.LinkIndex == 2 {
			expectedResult := &netlink.Route{
				LinkIndex: 2,
				Dst: &net.IPNet{
					IP:   net.ParseIP("169.254.172.0"),
					Mask: net.CIDRMask(22, 32),
				},
				Src: net.ParseIP("169.254.172.100"),
				Gw:  net.ParseIP("169.254.172.1"),
			}
			assert.EqualValuesf(t, expectedResult.String(), r.String(), "expect route %s needs to be added, received route %s", expectedResult.String(), r.Dst.String())
			return nil
		}
		// host route adding
		if r.LinkIndex == 100 {
			expectedResult := &netlink.Route{
				LinkIndex: 100,
				Dst: &net.IPNet{
					IP:   net.ParseIP("169.254.172.100"),
					Mask: net.CIDRMask(32, 32),
				},
			}
			assert.EqualValuesf(t, expectedResult.String(), r.String(), "expect route %s needs to be added, received route %s", expectedResult.String(), r.Dst.String())
			return nil
		}
		return fmt.Errorf("link index %d not valid", r.LinkIndex)
	}).Return(nil).Times(2)

	ipam.EXPECT().ConfigureIface("v4if0", gomock.Any()).Return(nil)
	procSys.EXPECT().Get("/proc/sys/net/ipv4/ip_forward").Return("0", nil)
	procSys.EXPECT().Set("/proc/sys/net/ipv4/ip_forward", "1").Return(nil)
	ipt.EXPECT().HasRandomFully().Return(true)
	ipt.EXPECT().ListChains("nat").Return([]string{"POSTROUTING", chain}, nil)

	expectedResults := []string{"nat CNI-E6 -d 224.0.0.0/4 -j ACCEPT -m comment --comment unit-test-comment",
		"nat CNI-E6 -j SNAT --to-source 192.168.0.23 -m comment --comment unit-test-comment --random-fully",
		"nat POSTROUTING -s 169.254.172.100 -j CNI-E6 -m comment --comment unit-test-comment"}
	expectedResultsMeet := []bool{false, false, false}
	ipt.EXPECT().AppendUnique("nat", gomock.Any(), gomock.Any()).Do(func(arg1 interface{}, arg2 interface{}, arg3 ...interface{}) {
		actualResult := arg1.(string) + " " + arg2.(string)
		for _, arg := range arg3 {
			actualResult += " " + arg.(string)
		}
		found := false
		for index, expect := range expectedResults {
			if expect == actualResult {
				expectedResultsMeet[index] = true
				found = true
			}
		}
		if !found {
			assert.Failf(t, "%s is not expected to add into iptables", actualResult)
		}
	}).Return(nil).AnyTimes()

	err = CmdAddEgressV4(procSys, ipt, ns, nsPath, ipam, link, veth, netConf, result, tmpResult, mtu, chain, comment, log)
	assert.NoError(t, err)

	for index, exp := range expectedResultsMeet {
		if !exp {
			assert.Failf(t, "%s is not added to ipatables", expectedResults[index])
		}
	}

}
