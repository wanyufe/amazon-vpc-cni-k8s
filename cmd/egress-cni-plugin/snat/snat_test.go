package snat

import (
	"net"
	"testing"

	mock_iptables "github.com/aws/amazon-vpc-cni-k8s/pkg/networkutils/mocks"
	"github.com/stretchr/testify/assert"
)

var multicastRange = "ff00::/8"
var target = net.ParseIP("2600::")
var src = net.ParseIP("fd00:1")
var chain = "CNI-E6-001"
var comment = "unit-test comment"
var randomizeSNAT = "hashrandom"

func TestAdd(t *testing.T) {
	ipt := mock_iptables.NewMockIptables()

	err := Add(ipt, multicastRange, target, src, chain, comment, randomizeSNAT)
	assert.NoError(t, err)
}
