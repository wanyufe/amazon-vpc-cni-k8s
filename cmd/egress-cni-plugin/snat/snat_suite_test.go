package snat_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSnat(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Snat Suite")
}
