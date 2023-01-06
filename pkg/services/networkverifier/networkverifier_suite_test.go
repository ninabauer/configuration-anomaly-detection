package networkverifier_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNetworkVerifier(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NetworkVerifier Suite")
}
