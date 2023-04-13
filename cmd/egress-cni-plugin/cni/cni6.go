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
	"net"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/cniutils"

	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/share"
	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/snat"
)

// Time duration CNI waits for an IPv6 address assigned to an interface
// to move to stable state before error'ing out.
const (
	WaitInterval       = 50 * time.Millisecond
	DadTimeout         = 10 * time.Second
	ipv6MulticastRange = "ff00::/8"
)

// setupHostIPv6Route adds a IPv6 route for traffic destined to container/pod from external/off-cluster
func setupHostIPv6Route(hostInterface *current.Interface, containerIPv6 net.IP, link netlinkwrapper.NetLink) error {
	hostIf, err := link.LinkByName(hostInterface.Name)
	if err != nil {
		return err
	}
	// set up to container return traffic route in host
	return link.RouteAdd(&netlink.Route{
		LinkIndex: hostIf.Attrs().Index,
		Scope:     netlink.SCOPE_HOST,
		Dst: &net.IPNet{
			IP:   containerIPv6,
			Mask: net.CIDRMask(128, 128),
		},
	})
}

func setupContainerVethIPv6(c *share.Context) (hostInterface, containerInterface *current.Interface, err error) {
	err = c.Ns.WithNetNSPath(c.NsPath, func(hostNS ns.NetNS) error {
		var hostVeth net.Interface
		var contVeth net.Interface

		hostVeth, contVeth, err = c.Veth.Setup(c.NetConf.IfName, c.Mtu, hostNS)
		if err != nil {
			return err
		}

		hostInterface = &current.Interface{
			Name: hostVeth.Name,
			Mac:  hostVeth.HardwareAddr.String(),
		}
		containerInterface = &current.Interface{
			Name:    contVeth.Name,
			Mac:     contVeth.HardwareAddr.String(),
			Sandbox: c.NsPath,
		}
		c.TmpResult.Interfaces = []*current.Interface{hostInterface, containerInterface}
		for _, ipc := range c.TmpResult.IPs {
			// Address (IPv6 ULA address) apply to the container veth interface - v6if0
			ipc.Interface = current.Int(1)
		}

		err = c.Ipam.ConfigureIface(c.NetConf.IfName, c.TmpResult)
		if err != nil {
			return err
		}

		return cniutils.WaitForAddressesToBeStable(c.Link, contVeth.Name, DadTimeout, WaitInterval)
	})
	return hostInterface, containerInterface, err
}

func setupContainerIPv6Route(netns nswrapper.NS, nsPath string, link netlinkwrapper.NetLink, hostInterface, containerInterface *current.Interface) (err error) {
	var hostIfIPv6 net.IP
	var hostNetIf netlink.Link
	var addrs []netlink.Addr
	hostNetIf, err = link.LinkByName(hostInterface.Name)
	if err != nil {
		return err
	}
	addrs, err = link.AddrList(hostNetIf, netlink.FAMILY_V6)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		// search for interface's link-local IPv6 address
		if addr.IP.To4() == nil && addr.IP.IsLinkLocalUnicast() {
			hostIfIPv6 = addr.IP
			break
		}
	}
	if hostIfIPv6 == nil {
		return fmt.Errorf("link-local IPv6 address not found on host interface %s", hostInterface.Name)
	}

	return netns.WithNetNSPath(nsPath, func(hostNS ns.NetNS) error {
		var containerVethIf netlink.Link
		containerVethIf, err = link.LinkByName(containerInterface.Name)
		if err != nil {
			return err
		}
		// set up from container off-cluster IPv6 route (egress)
		// all from container IPv6 traffic via host veth interface's link-local IPv6 address
		if err := link.RouteReplace(&netlink.Route{
			LinkIndex: containerVethIf.Attrs().Index,
			Dst: &net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, 128),
			},
			Scope: netlink.SCOPE_UNIVERSE,
			Gw:    hostIfIPv6}); err != nil {
			return fmt.Errorf("failed to add default IPv6 route via %s: %v", hostIfIPv6, err)
		}
		return nil
	})
}

func mergeResult(result *current.Result, tmpResult *current.Result) {
	lastInterfaceIndex := len(result.Interfaces)
	result.Interfaces = append(result.Interfaces, tmpResult.Interfaces...)
	for _, ip := range tmpResult.IPs {
		ip.Interface = current.Int(lastInterfaceIndex + *ip.Interface)
		result.IPs = append(result.IPs, ip)
	}
}

func disableInterfaceIPv6(c *share.Context) error { //netns nswrapper.NS, nsPath, ifName string) error {
	return c.Ns.WithNetNSPath(c.NsPath, func(hostNS ns.NetNS) error {
		var entry = "net/ipv6/conf/" + c.ArgsIfName + "/disable_ipv6"
		if content, err := c.Procsys.Get(entry); err == nil {
			if strings.TrimSpace(content) == "1" {
				return nil
			}
		}
		return c.Procsys.Set(entry, "1")
	})
}

//	containerIPv6, err := cniutils.GetIPsByInterfaceName(context.Link, context.Ns, context.NsPath, containerInterface.Name, func(ip net.IP) bool {
//			return ip.To4() == nil && ip.IsGlobalUnicast()
//		})
func getContainerIpv6GlobalAddrs(c *share.Context, ifName string) (containerIPv6 []net.IP, err error) {
	if c.NsPath != "" {
		err = c.Ns.WithNetNSPath(c.NsPath, func(hostNS ns.NetNS) error {
			link, err := c.Link.LinkByName(ifName)
			if err != nil {
				return err
			}
			addrs, err := c.Link.AddrList(link, netlink.FAMILY_V6)
			if err != nil {
				return err
			}
			for _, addr := range addrs {
				if addr.IP.IsGlobalUnicast() {
					containerIPv6 = append(containerIPv6, addr.IP)
				}
			}
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	return containerIPv6, nil
}

// CmdAddEgressV6 exec necessary settings to support IPv6 egress traffic in EKS IPv4 cluster
func CmdAddEgressV6(c *share.Context) (err error) { // ipt networkutils.IptablesIface, netns nswrapper.NS, nsPath string, ipam ipamwrapper.Ipam,
	//link netlinkwrapper.NetLink, veth vethwrapper.Veth, netConf *share.NetConf, result, tmpResult *current.Result,
	//mtu int, argsIfName, chain, comment string, log logger.Logger) error {
	// per best practice, a new veth pair is created between container ns and node ns
	// this newly created veth pair is used for container's egress IPv6 traffic
	// NOTE:
	//	1. link-local IPv6 addresses are automatically assigned to veth both ends.
	//	2. unique-local IPv6 address allocated from IPAM plugin is assigned to veth container end only
	//  3. veth node end has no unique-local IPv6 address assigned, only link-local IPv6 address
	//  4. IPv6 traffic egress through node primary interface (eth0) which has a IPv6 global unicast address
	//  5. all containers IPv6 egress traffic share node primary interface through SNAT

	// first disable IPv6 on container's primary interface (eth0)
	err = disableInterfaceIPv6(c)
	if err != nil {
		c.Log.Errorf("failed to disable IPv6 on container interface %s", c.ArgsIfName)
		return err
	}

	hostInterface, containerInterface, err := setupContainerVethIPv6(c)
	if err != nil {
		c.Log.Errorf("veth created failed, ns: %s name: %s, mtu: %d, ipam-result: %+v err: %v",
			c.NsPath, c.NetConf.IfName, c.Mtu, *c.TmpResult, err)
		return err
	}
	c.Log.Debugf("veth pair created for container IPv6 egress traffic, container interface: %s ,host interface: %s",
		containerInterface.Name, hostInterface.Name)

	containerIPv6, err := getContainerIpv6GlobalAddrs(c, containerInterface.Name)
	if err != nil {
		return err
	}
	if len(containerIPv6) > 1 {
		c.Log.Warnf("more than one IPv6 global unicast address found, ifName: %s, IPs: %s", containerInterface.Name, containerIPv6)
	} else if len(containerIPv6) < 1 {
		c.Log.Errorf("no IPv6 global unicast address found, ifName: %s, IPs: %s", containerInterface.Name, containerIPv6)
		return fmt.Errorf("no IPv6 global unicast address found, ifName: %s, IPs: %s", containerInterface.Name, containerIPv6)
	}
	err = setupContainerIPv6Route(c.Ns, c.NsPath, c.Link, hostInterface, containerInterface)
	if err != nil {
		c.Log.Errorf("setupContainerIPv6Route failed: %v", err)
		return err
	}
	c.Log.Debugf("container route set up successfully")

	err = setupHostIPv6Route(hostInterface, containerIPv6[0], c.Link)
	if err != nil {
		c.Log.Errorf("setupHostIPv6Route failed: %v", err)
		return err
	}
	c.Log.Debugf("host IPv6 route set up successfully")

	// set up SNAT in host for container IPv6 egress traffic
	// following line adds an ip6tables entries to NAT from pod IPv6 address to node IPv6 address assigned to primary ENI
	err = snat.Add(c.Iptv6, c.NetConf.NodeIP, containerIPv6[0], ipv6MulticastRange, c.Chain, c.Comment, c.NetConf.RandomizeSNAT)
	if err != nil {
		c.Log.Errorf("setup host snat failed: %v", err)
		return err
	}

	c.Log.Debugf("host IPv6 SNAT set up successfully")

	mergeResult(c.Result, c.TmpResult)
	c.Log.Debugf("output result: %+v", *c.Result)

	// Pass through the previous result
	return types.PrintResult(c.Result, c.NetConf.CNIVersion)
}

// CmdDelEgressV6 exec clear the setting to support IPv6 egress traffic in EKS IPv4 cluster
func CmdDelEgressV6(c *share.Context) (err error) {
	var contIPAddrs []netlink.Addr

	if c.NsPath != "" {
		err = c.Ns.WithNetNSPath(c.NsPath, func(hostNS ns.NetNS) error {
			var containerLink netlink.Link
			containerLink, err = c.Link.LinkByName(c.NetConf.IfName)
			if err != nil {
				c.Log.Debugf("failed to get link by name %s: %v", c.NetConf.IfName, err)
				return nil
			}
			contIPAddrs, err = c.Link.AddrList(containerLink, netlink.FAMILY_V6)
			if err != nil {
				c.Log.Debugf("failed to get container link %s IPv6 address, host may leave NAT rules uncleared: %v", containerLink.Attrs().Name, err)
			}
			err = c.Link.LinkDel(containerLink)
			if err != nil {
				c.Log.Debugf("failed to delete veth %s in container: %v", containerLink.Attrs().Name, err)
			} else {
				c.Log.Debugf("Successfully deleted veth %s in container", containerLink.Attrs().Name)
			}
			return err
		})
	}

	// range loop exec 0 times if confIPNets is nil
	for _, contIPAddr := range contIPAddrs {
		// remove host SNAT chain/rule for container
		err = snat.Del(c.Iptv6, contIPAddr.IP, c.Chain, c.Comment)
		if err != nil {
			c.Log.Errorf("Delete host SNAT for container IPv6 %s failed: %v.", contIPAddr.IP.String(), err)
		}
		c.Log.Debugf("Successfully deleted SNAT chain/rule for container IPv6 egress traffic: %s", contIPAddr.IP.String())
	}

	return nil
}
