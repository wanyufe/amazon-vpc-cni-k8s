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

var _ = Describe("cni4", func() {
	var ctrl *gomock.Controller
	var ipt *mock_networkutils.MockIptablesIface
	var context share.Context
	var allowedResults []string
	var actualResults []string

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		ipt = mock_networkutils.NewMockIptablesIface(ctrl)
		context = setupContext(ctrl, ipt)
		allowedResults = []string{"nat CNI-E6 -d 224.0.0.0/4 -j ACCEPT -m comment --comment unit-test-comment",
			"nat CNI-E6 -j SNAT --to-source 192.168.0.23 -m comment --comment unit-test-comment --random-fully",
			"nat POSTROUTING -s 169.254.172.100 -j CNI-E6 -m comment --comment unit-test-comment"}
		actualResults = []string{}
	})
	AfterEach(func() {
		ctrl.Finish()
	})

	Context("IPv4 egress setup when container is added", func() {
		It("iptable chain and rules are added", func() {
			setupAddExpect(context, &actualResults)

			err := cni.CmdAddEgressV4(&context)
			Ω(err).ShouldNot(HaveOccurred())
			Ω(len(actualResults)).Should(Equal(3))
			for index, result := range actualResults {
				Ω(result).Should(Equal(allowedResults[index]))
			}
		})
	})
})

func setupContext(ctrl *gomock.Controller, ipt *mock_networkutils.MockIptablesIface) share.Context {
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
			NodeIP:         net.ParseIP("192.168.0.23"),
			IfName:         "v4if0",
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

func setupAddExpect(c share.Context, acturalResults *[]string) {
	nsParent, err := _ns.GetCurrentNS()
	Ω(err).ToNot(HaveOccurred())

	macHost := [6]byte{0xCB, 0xB8, 0x33, 0x4C, 0x88, 0x4F}
	macCont := [6]byte{0xCC, 0xB8, 0x33, 0x4C, 0x88, 0x4F}

	c.Ns.(*mock_nswrapper.MockNS).EXPECT().WithNetNSPath(c.NsPath, gomock.Any()).Do(func(_nsPath string, f func(_ns.NetNS) error) {
		f(nsParent)
	}).Return(nil)

	c.Veth.(*mock_veth.MockVeth).EXPECT().Setup(c.NetConf.IfName, c.Mtu, gomock.Any()).Return(
		net.Interface{
			Name:         "vethxxxx",
			HardwareAddr: macHost[:],
		},
		net.Interface{
			Name:         "v4if0",
			HardwareAddr: macCont[:],
		},
		nil)

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Return(nil)
	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().RouteAdd(gomock.Any()).Return(nil)

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().LinkByName("vethxxxx").Return(
		&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "vethxxxx",
				Index: 100,
			},
		}, nil)
	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().LinkByName("v4if0").Return(
		&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  "v4if0",
				Index: 2,
			},
		}, nil)
	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().RouteDel(gomock.Any()).Do(func(arg1 interface{}) error {
		r := arg1.(*netlink.Route)
		expectedResult := &net.IPNet{
			IP:   net.ParseIP("169.254.172.0"),
			Mask: net.CIDRMask(22, 32),
		}
		Ω(r.Dst.String()).To(Equal(expectedResult.String()))
		return nil
	}).Return(nil)

	c.Link.(*mock_netlinkwrapper.MockNetLink).EXPECT().RouteAdd(gomock.Any()).Do(func(arg1 interface{}) error {
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
			Ω(r.String()).To(Equal(expectedResult.String()))
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
			Ω(r.String()).To(Equal(expectedResult.String()))
			return nil
		}
		return fmt.Errorf("link index %d not valid", r.LinkIndex)
	}).Return(nil).Times(2)

	c.Ipam.(*mock_ipamwrapper.MockIpam).EXPECT().ConfigureIface("v4if0", gomock.Any()).Return(nil)
	c.Procsys.(*mock_procsyswrapper.MockProcSys).EXPECT().Get("net/ipv4/ip_forward").Return("0", nil)
	c.Procsys.(*mock_procsyswrapper.MockProcSys).EXPECT().Set("net/ipv4/ip_forward", "1").Return(nil)
	c.Iptv4.(*mock_networkutils.MockIptablesIface).EXPECT().HasRandomFully().Return(true)
	c.Iptv4.(*mock_networkutils.MockIptablesIface).EXPECT().ListChains("nat").Return([]string{"POSTROUTING", c.Chain}, nil)

	c.Iptv4.(*mock_networkutils.MockIptablesIface).EXPECT().AppendUnique("nat", gomock.Any(), gomock.Any()).Do(func(arg1 interface{}, arg2 interface{}, arg3 ...interface{}) {
		actualResult := arg1.(string) + " " + arg2.(string)
		for _, arg := range arg3 {
			actualResult += " " + arg.(string)
		}
		*acturalResults = append(*acturalResults, actualResult)
	}).Return(nil).Times(3)
}
