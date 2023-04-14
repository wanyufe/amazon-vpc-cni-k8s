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

package cni_test

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/cni"
	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/share"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/logger"

	"github.com/vishvananda/netlink"

	mock_netlinkwrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper/mocks"

	mock_nswrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper/mocks"

	"github.com/containernetworking/cni/pkg/types/current"
	_ns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/golang/mock/gomock"

	mock_ipamwrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/ipamwrapper/mocks"
	mock_networkutils "github.com/aws/amazon-vpc-cni-k8s/pkg/networkutils/mocks"
	mock_procsyswrapper "github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper/mocks"
	mock_veth "github.com/aws/amazon-vpc-cni-k8s/pkg/vethwrapper/mocks"
)

var _ = Describe("cni6", func() {
	var ctrl *gomock.Controller
	var ipt *mock_networkutils.MockIptablesIface
	var context share.Context

	// add
	var expectIptablesRules []string
	var actualIptablesRules []string
	var expectRouteAdd []string
	var actualRouteAdd []string
	var expectRouteReplace []string
	var actualRouteReplace []string

	// del
	var expectLinkDel []string
	var actualLinkDel []string
	var expectIptablesDel []string
	var actualIptablesDel []string

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		ipt = mock_networkutils.NewMockIptablesIface(ctrl)
	})
	AfterEach(func() {
		ctrl.Finish()
	})

	Context("when container del/remove", func() {
		BeforeEach(func() {
			context = setupDelContextV6(ctrl, ipt)

			expectLinkDel = []string{"link del - name: v6if0"}
			actualLinkDel = []string{}

			expectIptablesDel = []string{
				"nat POSTROUTING -s fd00::10 -j CNI-E6 -m comment --comment unit-test-comment",
				"clear chain nat CNI-E6",
				"del chain nat CNI-E6"}
			actualIptablesDel = []string{}
			setupDelExpectV6(context, &actualLinkDel, &actualIptablesDel)
			err := cni.CmdDelEgressV6(&context)
			Ω(err).ShouldNot(HaveOccurred())
		})
		It("iptables chain and rules are removed", func() {
			Ω(actualIptablesDel).Should(Equal(expectIptablesDel))
		})
		It("link removed in container", func() {
			Ω(actualLinkDel).Should(Equal(expectLinkDel))
		})
	})

	Context("when container add/create", func() {
		BeforeEach(func() {
			context = setupAddContextV6(ctrl, ipt)
			expectIptablesRules = []string{
				"nat CNI-E6 -d ff00::/8 -j ACCEPT -m comment --comment unit-test-comment",
				"nat CNI-E6 -j SNAT --to-source 2600:: -m comment --comment unit-test-comment --random-fully",
				"nat POSTROUTING -s fd00::10 -j CNI-E6 -m comment --comment unit-test-comment",
			}
			actualIptablesRules = []string{}

			expectRouteAdd = []string{
				"{Ifindex: 100 Dst: fd00::10/128 Src: <nil> Gw: <nil> Flags: [] Table: 0}",
			}
			actualRouteAdd = []string{}

			expectRouteReplace = []string{"{Ifindex: 2 Dst: ::/0 Src: <nil> Gw: fe80::10 Flags: [] Table: 0}"}
			actualRouteReplace = []string{}

			setupAddExpectV6(context, &actualIptablesRules, &actualRouteAdd, &actualRouteReplace) //, &actualRouteDel)
			err := cni.CmdAddEgressV6(&context)
			Ω(err).ShouldNot(HaveOccurred())
		})

		It("iptables chain and rules are added", func() {
			Ω(actualIptablesRules).To(Equal(expectIptablesRules))
		})
		It("route replaced in container and host", func() {
			Ω(actualRouteReplace).To(Equal(expectRouteReplace))
		})
		It("route added in container and host", func() {
			Ω(actualRouteAdd).To(Equal(expectRouteAdd))
		})
	})

})

func setupAddContextV6(ctrl *gomock.Controller, ipt *mock_networkutils.MockIptablesIface) share.Context {
	return share.Context{
		Procsys: mock_procsyswrapper.NewMockProcSys(ctrl),
		Ns:      mock_nswrapper.NewMockNS(ctrl),
		NsPath:  "/var/run/netns/cni-xxxx",
		Ipam:    mock_ipamwrapper.NewMockIpam(ctrl),
		Link:    mock_netlinkwrapper.NewMockNetLink(ctrl),
		Veth:    mock_veth.NewMockVeth(ctrl),
		NetConf: &share.NetConf{
			NetConf: types.NetConf{
				CNIVersion: "0.4.0",
			},
			NodeIP:         net.ParseIP("2600::"),
			IfName:         "v6if0",
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

func setupAddExpectV6(c share.Context, actualIptablesRules, actualRouteAdd, actualRouteReplace *[]string) {
	nsParent, err := _ns.GetCurrentNS()
	Ω(err).ToNot(HaveOccurred())

	macHost := [6]byte{0xCB, 0xB8, 0x33, 0x4C, 0x88, 0x4F}
	macCont := [6]byte{0xCC, 0xB8, 0x33, 0x4C, 0x88, 0x4F}

	c.Ns.(*mock_nswrapper.MockNS).EXPECT().WithNetNSPath(c.NsPath, gomock.Any()).Do(func(_nsPath string, f func(_ns.NetNS) error) {
		f(nsParent)
	}).Return(nil).AnyTimes()

	c.Veth.(*mock_veth.MockVeth).EXPECT().Setup(c.NetConf.IfName, c.Mtu, gomock.Any()).Return(
		net.Interface{
			Name:         "vethxxxx",
			HardwareAddr: macHost[:],
		},
		net.Interface{
			Name:         "v6if0",
			HardwareAddr: macCont[:],
		},
		nil)

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().LinkByName("vethxxxx").Return(
		&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "vethxxxx",
				Index: 100,
			},
		}, nil).AnyTimes()
	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().LinkByName("v6if0").Return(
		&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "v6if0",
				Index: 2,
			},
		}, nil).AnyTimes()
	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().AddrList(gomock.Any(), netlink.FAMILY_V6).DoAndReturn(
		func(arg1 interface{}, _ interface{}) ([]netlink.Addr, error) {
			link := arg1.(netlink.Link)
			if link.Attrs().Name == "v6if0" {
				return []netlink.Addr{
					{
						IPNet: &net.IPNet{
							IP:   net.ParseIP("fd00::10"),
							Mask: net.CIDRMask(8, 128),
						},
						LinkIndex: 2,
					},
				}, nil
			} else if link.Attrs().Name == "vethxxxx" {
				return []netlink.Addr{
					{
						IPNet: &net.IPNet{
							IP:   net.ParseIP("fe80::10"),
							Mask: net.CIDRMask(64, 128),
						},
						LinkIndex: 100,
					},
				}, nil
			}
			return nil, fmt.Errorf("unexpected call with link name %s", link.Attrs().Name)
		}).AnyTimes()

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().RouteReplace(gomock.Any()).Do(func(arg1 interface{}) error {
		r := arg1.(*netlink.Route)
		*actualRouteReplace = append(*actualRouteReplace, r.String())
		return nil
	}).Return(nil)

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().RouteAdd(gomock.Any()).Do(func(arg1 interface{}) error {
		r := arg1.(*netlink.Route)
		// container route adding
		*actualRouteAdd = append(*actualRouteAdd, r.String())
		return nil
	}).Return(nil).Times(1)

	c.Ipam.(*mock_ipamwrapper.MockIpam).EXPECT().ConfigureIface("v6if0", gomock.Any()).Return(nil)
	c.Procsys.(*mock_procsyswrapper.MockProcSys).EXPECT().Get("net/ipv6/conf/eth0/disable_ipv6").Return("0", nil)
	c.Procsys.(*mock_procsyswrapper.MockProcSys).EXPECT().Set("net/ipv6/conf/eth0/disable_ipv6", "1").Return(nil)
	c.Iptv6.(*mock_networkutils.MockIptablesIface).EXPECT().HasRandomFully().Return(true)
	c.Iptv6.(*mock_networkutils.MockIptablesIface).EXPECT().ListChains("nat").Return([]string{"POSTROUTING", c.Chain}, nil)

	c.Iptv6.(*mock_networkutils.MockIptablesIface).EXPECT().AppendUnique("nat", gomock.Any(), gomock.Any()).Do(func(arg1 interface{}, arg2 interface{}, arg3 ...interface{}) {
		actualResult := arg1.(string) + " " + arg2.(string)
		for _, arg := range arg3 {
			actualResult += " " + arg.(string)
		}
		*actualIptablesRules = append(*actualIptablesRules, actualResult)
	}).Return(nil).Times(3)
}

func setupDelExpectV6(c share.Context, actualLinkDel, actualIptablesDel *[]string) {
	nsParent, err := _ns.GetCurrentNS()
	Ω(err).ToNot(HaveOccurred())

	c.Ns.(*mock_nswrapper.MockNS).EXPECT().WithNetNSPath(c.NsPath, gomock.Any()).Do(func(_nsPath string, f func(_ns.NetNS) error) {
		f(nsParent)
	}).Return(nil)

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().LinkByName("v6if0").Return(
		&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "v6if0",
				Index: 2,
			},
		}, nil)

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().AddrList(gomock.Any(), netlink.FAMILY_V6).Return(
		[]netlink.Addr{
			{
				IPNet: &net.IPNet{
					IP:   net.ParseIP("fd00::10"),
					Mask: net.CIDRMask(8, 128),
				},
				LinkIndex: 2,
			},
		}, nil).AnyTimes()

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().LinkDel(gomock.Any()).Do(
		func(arg1 interface{}) error {
			link := arg1.(netlink.Link)
			*actualLinkDel = append(*actualLinkDel, "link del - name: "+link.Attrs().Name)
			return nil
		}).Return(nil)

	c.Iptv6.(*mock_networkutils.MockIptablesIface).EXPECT().Delete("nat", "POSTROUTING", gomock.Any()).Do(
		func(arg1 interface{}, arg2 interface{}, arg3 ...interface{}) {
			actualResult := arg1.(string) + " " + arg2.(string)
			for _, arg := range arg3 {
				actualResult += " " + arg.(string)
			}
			*actualIptablesDel = append(*actualIptablesDel, actualResult)
		}).Return(nil).AnyTimes()

	c.Iptv6.(*mock_networkutils.MockIptablesIface).EXPECT().ClearChain("nat", "CNI-E6").Do(
		func(arg1 interface{}, arg2 interface{}) {
			actualResult := arg1.(string) + " " + arg2.(string)
			*actualIptablesDel = append(*actualIptablesDel, "clear chain "+actualResult)
		}).Return(nil).AnyTimes()

	c.Iptv6.(*mock_networkutils.MockIptablesIface).EXPECT().DeleteChain("nat", "CNI-E6").Do(
		func(arg1 interface{}, arg2 interface{}) {
			actualResult := arg1.(string) + " " + arg2.(string)
			*actualIptablesDel = append(*actualIptablesDel, "del chain "+actualResult)
		}).Return(nil).AnyTimes()
}
func setupDelContextV6(ctrl *gomock.Controller, ipt *mock_networkutils.MockIptablesIface) share.Context {
	return share.Context{
		Procsys: mock_procsyswrapper.NewMockProcSys(ctrl),
		Ns:      mock_nswrapper.NewMockNS(ctrl),
		NsPath:  "/var/run/netns/cni-xxxx",
		Ipam:    mock_ipamwrapper.NewMockIpam(ctrl),
		Link:    mock_netlinkwrapper.NewMockNetLink(ctrl),
		Veth:    mock_veth.NewMockVeth(ctrl),
		NetConf: &share.NetConf{
			NetConf: types.NetConf{
				CNIVersion: "0.4.0",
			},
			NodeIP:         net.ParseIP("2600::"),
			IfName:         "v6if0",
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
