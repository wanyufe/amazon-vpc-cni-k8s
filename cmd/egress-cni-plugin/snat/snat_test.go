package snat_test

import (
	"net"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/snat"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/networkutils"
	mock_networkutils "github.com/aws/amazon-vpc-cni-k8s/pkg/networkutils/mocks"
)

var (
	ipv6MulticastRange = "ff00::/8"
	ipv4MulticastRange = "224.0.0.0/4"

	containerIpv4 = net.ParseIP("169.254.172.100")
	containerIpv6 = net.ParseIP("fd00::10")
	nodeIp        = net.ParseIP("2600::")

	chain   = "CNI-E6"
	comment = "unit-test-comment"
	rndSNAT = "hashrandom"
)

var _ = Describe("Snat", func() {
	var ctrl *gomock.Controller
	var ipt *mock_networkutils.MockIptablesIface
	//var context share.Context

	var expectChain []string
	var actualChain []string

	var expectRule []string
	var actualRule []string

	var expectClearChain []string
	var actualClearChain []string

	var expectDeleteChain []string
	var actualDeleteChain []string

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
	})
	AfterEach(func() {
		ctrl.Finish()
	})

	Context("when container add/create", func() {
		BeforeEach(func() {
			ipt = mock_networkutils.NewMockIptablesIface(ctrl)

			expectChain = []string{chain}
			actualChain = []string{}

			expectRule = []string{
				"nat CNI-E6 -d ff00::/8 -j ACCEPT -m comment --comment unit-test-comment",
				"nat CNI-E6 -j SNAT --to-source 2600:: -m comment --comment unit-test-comment --random",
				"nat POSTROUTING -s fd00::10 -j CNI-E6 -m comment --comment unit-test-comment",
			}
			actualRule = []string{}

			setupAddExpect(ipt, &actualChain, &actualRule)

			err := snat.Add(ipt, nodeIp, containerIpv6, ipv6MulticastRange, chain, comment, rndSNAT)
			Ω(err).ShouldNot(HaveOccurred())
		})

		It("create iptables chain", func() {
			Ω(actualChain).Should(Equal(expectChain))
		})

		It("create iptables rule", func() {
			Ω(actualRule).Should(Equal(expectRule))
		})
	})

	Context("when container delete/remove", func() {
		BeforeEach(func() {
			ipt = mock_networkutils.NewMockIptablesIface(ctrl)

			expectClearChain = []string{chain}
			actualClearChain = []string{}

			expectDeleteChain = []string{chain}
			actualDeleteChain = []string{}

			expectRule = []string{"nat POSTROUTING -s fd00::10 -j CNI-E6 -m comment --comment unit-test-comment"}
			actualRule = []string{}

			setupDelExpect(ipt, &actualClearChain, &actualDeleteChain, &actualRule)

			err := snat.Del(ipt, containerIpv6, chain, comment)
			Ω(err).ShouldNot(HaveOccurred())
		})

		It("clear/delete iptables chain", func() {
			Ω(actualClearChain).Should(Equal(expectClearChain))
			Ω(actualDeleteChain).Should(Equal(expectDeleteChain))
		})

		It("delete iptables rule", func() {
			Ω(actualRule).Should(Equal(expectRule))
		})
	})
})

func setupAddExpect(ipt networkutils.IptablesIface, actualNewChain, actualNewRule *[]string) {
	ipt.(*mock_networkutils.MockIptablesIface).EXPECT().ListChains("nat").Return(
		[]string{"POSTROUTING"}, nil)

	ipt.(*mock_networkutils.MockIptablesIface).EXPECT().NewChain("nat", gomock.Any()).Do(func(_, arg1 interface{}) {
		chain := arg1.(string)
		*actualNewChain = append(*actualNewChain, chain)
	}).Return(nil)

	ipt.(*mock_networkutils.MockIptablesIface).EXPECT().AppendUnique("nat", gomock.Any(), gomock.Any()).Do(func(arg1, arg2 interface{}, arg3 ...interface{}) {
		rule := arg1.(string) + " " + arg2.(string)
		for _, arg := range arg3 {
			rule += " " + arg.(string)
		}
		*actualNewRule = append(*actualNewRule, rule)
	}).Return(nil).AnyTimes()
}

func setupDelExpect(ipt networkutils.IptablesIface, actualClearChain, actualDeleteChain, actualRule *[]string) {
	ipt.(*mock_networkutils.MockIptablesIface).EXPECT().ClearChain("nat", gomock.Any()).Do(func(_, arg2 interface{}) {
		*actualClearChain = append(*actualClearChain, arg2.(string))
	}).Return(nil)

	ipt.(*mock_networkutils.MockIptablesIface).EXPECT().DeleteChain("nat", gomock.Any()).Do(func(_, arg2 interface{}) {
		*actualDeleteChain = append(*actualDeleteChain, arg2.(string))
	}).Return(nil)

	ipt.(*mock_networkutils.MockIptablesIface).EXPECT().Delete("nat", gomock.Any(), gomock.Any()).Do(func(arg1, arg2 interface{}, arg3 ...interface{}) {
		rule := arg1.(string) + " " + arg2.(string)
		for _, arg := range arg3 {
			rule += " " + arg.(string)
		}
		*actualRule = append(*actualRule, rule)
	}).Return(nil).AnyTimes()
}
