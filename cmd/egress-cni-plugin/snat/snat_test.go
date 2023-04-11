package snat

import (
	"net"
	"strings"
	"testing"

	mock_iptables "github.com/aws/amazon-vpc-cni-k8s/pkg/networkutils/mocks"
	"github.com/stretchr/testify/assert"
)

var multicastRange = "ff00::/8"
var target = net.ParseIP("2600::")
var src = net.ParseIP("fd00::1")
var chain = "CNI-E6-001"
var comment = "unit-test-comment"
var randomizeSNAT = "hashrandom"

var expectedChainRules = []string{
	"-A CNI-E6-001 -d ff00::/8 -j ACCEPT -m comment --comment unit-test-comment",
	"-A CNI-E6-001 -j SNAT --to-source 2600:: -m comment --comment unit-test-comment --random",
}
var expectedPOSTROUTINGRules = []string{
	"-A POSTROUTING -s fd00::1 -j CNI-E6-001 -m comment --comment unit-test-comment",
}

func TestAdd(t *testing.T) {

	ipt := mock_iptables.NewMockIptables()

	err := Add(ipt, multicastRange, target, src, chain, comment, randomizeSNAT)
	assert.NoError(t, err)

	rules, err := ipt.List("nat", chain)
	assert.NoError(t, err)

	for index, rule := range rules {
		assert.EqualValuesf(t, expectedChainRules[index], rule, "%s chain rules, expected: %s, actual: %s", chain, expectedChainRules[index], rule)
	}

	rules, err = ipt.List("nat", "POSTROUTING")
	assert.NoError(t, err)

	for index, rule := range rules {
		assert.EqualValuesf(t, expectedPOSTROUTINGRules[index], rule, "POSTROUTING chain rules, expected: %s, actual: %s", expectedPOSTROUTINGRules[index], rule)
	}
}

func TestDel(t *testing.T) {
	ipt := mock_iptables.NewMockIptables()

	// pre-populate chain/rule into iptables
	err := ipt.NewChain("nat", chain)
	assert.NoError(t, err)

	for _, rule := range expectedChainRules {
		err = ipt.AppendUnique("nat", chain, strings.Split(rule, " ")[2:]...)
		assert.NoError(t, err)
	}

	for _, rule := range expectedPOSTROUTINGRules {
		err = ipt.AppendUnique("nat", "POSTROUTING", strings.Split(rule, " ")[2:]...)
		assert.NoError(t, err)
	}

	err = Del(ipt, src, chain, comment)
	assert.NoError(t, err)

	var expectedLeftRule []string

	actualChainRules, err := ipt.List("nat", chain)
	assert.NoError(t, err)
	assert.EqualValuesf(t, expectedLeftRule, actualChainRules, "chain %s has rules not removed, %s", chain, actualChainRules)

	actualPOSTROUTINGRules, err := ipt.List("nat", "POSTROUTING")
	assert.NoError(t, err)

	assert.EqualValuesf(t, expectedLeftRule, actualPOSTROUTINGRules, "chain %s has rules not removed, %s", "POSTROUTING", actualPOSTROUTINGRules)

}
