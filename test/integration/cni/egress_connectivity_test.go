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

	"github.com/aws/amazon-vpc-cni-k8s/test/framework/resources/k8s/manifest"
	k8sUtils "github.com/aws/amazon-vpc-cni-k8s/test/framework/resources/k8s/utils"
	"github.com/aws/amazon-vpc-cni-k8s/test/framework/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
)

const (
	publicIpv6UrlForTesting = "https://ipv6.icanhazip.com"
	publicIpv4UrlForTesting = "https://ip.icanhazip.com"
)

// Verifies connectivity to deployment behind different service types
var _ = Describe("[CANARY] test container IPv6 egress connectivity", func() {
	var err error
	var address string
	var enable_v6_egress string
	var isIpv4Cluster bool
	var isIpv6Cluster bool
	// Test container that verifies connectivity to en external IPv6 using IPv6 only
	var testerContainer v1.Container
	var instancesWithNoIpv6OnPrimaryENI []string
	var instancesWithNoIpv4OnPrimaryENI []string
	var nodeList v1.NodeList
	var nodeIps map[string]*string

	BeforeEach(func() {
		err = nil
		address = ""
		enable_v6_egress = "false"
		isIpv4Cluster = false
		isIpv6Cluster = false
		testerContainer = v1.Container{}
		instancesWithNoIpv6OnPrimaryENI = []string{}
		instancesWithNoIpv4OnPrimaryENI = []string{}
		nodeIps = make(map[string]*string)

		clusterOutput, err := f.CloudServices.EKS().DescribeCluster(f.Options.ClusterName)
		Expect(err).NotTo(HaveOccurred())
		if *clusterOutput.Cluster.KubernetesNetworkConfig.IpFamily == "ipv4" {
			isIpv4Cluster = true
			enable_v6_egress = "true"
		} else if *clusterOutput.Cluster.KubernetesNetworkConfig.IpFamily == "ipv4" {
			isIpv6Cluster = true
		}

		nodeList, err = f.K8sResourceManagers.NodeManager().GetAllNodes()
		Expect(err).ToNot(HaveOccurred())

		for _, node := range nodeList.Items {
			instance, err := f.CloudServices.EC2().DescribeInstance(k8sUtils.GetInstanceIDFromNode(node))
			Expect(err).ToNot(HaveOccurred())
			if isIpv4Cluster {
				nodeIps[node.Name] = instance.Ipv6Address
				if instance.Ipv6Address == nil {
					instancesWithNoIpv6OnPrimaryENI = append(instancesWithNoIpv6OnPrimaryENI, node.Name)
				}
			} else if isIpv6Cluster {
				nodeIps[node.Name] = instance.PublicIpAddress
				if instance.PublicIpAddress == nil {
					instancesWithNoIpv4OnPrimaryENI = append(instancesWithNoIpv4OnPrimaryENI, node.Name)
				}
			}
		}
	})
	JustBeforeEach(func() {
		if isIpv4Cluster && len(instancesWithNoIpv6OnPrimaryENI) > 0 {
			Skip(fmt.Sprintf("egress connectivity testing skipped: instances %s primary ENI has no global IPv6 address", instancesWithNoIpv6OnPrimaryENI))
		}
		if isIpv6Cluster && len(instancesWithNoIpv4OnPrimaryENI) > 0 {
			Skip(fmt.Sprintf("egress connectivity testing skipped: instances %s primary ENI has no global IPv4 address", instancesWithNoIpv4OnPrimaryENI))
		}

		By("enabling IPv6 egress supporting and wait daemon set to be ready")
		if isIpv4Cluster {
			k8sUtils.AddEnvVarToDaemonSetAndWaitTillUpdated(f, utils.AwsNodeName, utils.AwsNodeNamespace, utils.AwsNodeName, map[string]string{
				"ENABLE_V6_EGRESS": enable_v6_egress,
			})
		}

		if isIpv4Cluster {
			testerContainer = manifest.NewCurlContainer().
				Command([]string{"curl"}).
				Args([]string{"--silent", "-6", fmt.Sprintf("%s", publicIpv6UrlForTesting)}).
				Build()
		} else if isIpv6Cluster {
			testerContainer = manifest.NewCurlContainer().
				Command([]string{"curl"}).
				Args([]string{"--silent", "-4", fmt.Sprintf("%s", publicIpv4UrlForTesting)}).
				Build()
		}

		egressPod := manifest.NewDefaultPodBuilder().
			Name("egress-pod").
			Container(testerContainer).
			Build()

		egressPod, err = f.K8sResourceManagers.PodManager().
			CreateAndWaitTillPodCompleted(egressPod)
		Expect(err).ToNot(HaveOccurred())

		address, err = f.K8sResourceManagers.PodManager().
			PodLogs(egressPod.Namespace, egressPod.Name)
		Expect(err).ToNot(HaveOccurred())

		Expect(address).Should(Equal(*nodeIps[egressPod.Spec.NodeName] + "\n"))

		err = f.K8sResourceManagers.PodManager().DeleteAndWaitTillPodDeleted(egressPod)
		Expect(err).ToNot(HaveOccurred())
	})

	JustAfterEach(func() {
	})

	Context("when a container is created in", func() {
		FIt("retrieved IP address should match instance primary ENI IP", func() {})
	})
})
