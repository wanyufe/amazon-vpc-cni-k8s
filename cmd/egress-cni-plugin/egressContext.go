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

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"

	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/snat"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/hostipamwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/iptableswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/cniutils"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/logger"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/vethwrapper"
)

const (
	ipv4MulticastRange = "224.0.0.0/4"
	// WaitInterval Time duration CNI waits before next check for an IPv6 address assigned to an interface
	// to move to stable state.
	WaitInterval = 50 * time.Millisecond
	// DadTimeout Time duration CNI waits for an IPv6 address assigned to an interface
	// to move to stable state before error'ing out.
	DadTimeout         = 10 * time.Second
	ipv6MulticastRange = "ff00::/8"
)

// EgressContext includes all info to run container ADD/DEL action
type EgressContext struct {
	Procsys       procsyswrapper.ProcSys
	Ipam          hostipamwrapper.HostIpam
	Link          netlinkwrapper.NetLink
	Ns            nswrapper.NS
	NsPath        string
	ArgsIfName    string
	Veth          vethwrapper.Veth
	IPTablesIface iptableswrapper.IPTablesIface
	IptCreator    func(iptables.Protocol) (iptableswrapper.IPTablesIface, error)

	NetConf   *NetConf
	Result    *current.Result
	TmpResult *current.Result
	Log       logger.Logger

	Mtu     int
	Chain   string
	Comment string
}

func (c *EgressContext) setupContainerVethv4() (*current.Interface, *current.Interface, error) {
	// The IPAM result will be something like IP=192.168.3.5/24, GW=192.168.3.1.
	// What we want is really a point-to-point link but veth does not support IFF_POINTTOPOINT.
	// Next best thing would be to let it ARP but set interface to 192.168.3.5/32 and
	// add a route like "192.168.3.0/24 via 192.168.3.1 dev $ifName".
	// Unfortunately that won't work as the GW will be outside the interface's subnet.

	// Our solution is to configure the interface with 192.168.3.5/24, then delete the
	// "192.168.3.0/24 dev $ifName" route that was automatically added. Then we add
	// "192.168.3.1/32 dev $ifName" and "192.168.3.0/24 via 192.168.3.1 dev $ifName".
	// In other words we force all traffic to ARP via the gateway except for GW itself.

	hostInterface := &current.Interface{}
	containerInterface := &current.Interface{}

	err := c.Ns.WithNetNSPath(c.NsPath, func(hostNS ns.NetNS) error {
		hostVeth, contVeth0, err := c.Veth.Setup(c.NetConf.IfName, c.Mtu, hostNS)
		if err != nil {
			return err
		}
		hostInterface.Name = hostVeth.Name
		hostInterface.Mac = hostVeth.HardwareAddr.String()
		containerInterface.Name = contVeth0.Name
		containerInterface.Mac = contVeth0.HardwareAddr.String()
		containerInterface.Sandbox = c.NsPath

		for _, ipc := range c.TmpResult.IPs {
			// All addresses apply to the container veth interface
			ipc.Interface = current.Int(1)
		}

		c.TmpResult.Interfaces = []*current.Interface{hostInterface, containerInterface}

		if err = c.Ipam.ConfigureIface(c.NetConf.IfName, c.TmpResult); err != nil {
			return err
		}

		contVeth, err := c.Link.LinkByName(c.NetConf.IfName)
		if err != nil {
			return fmt.Errorf("failed to look up %q: %v", c.NetConf.IfName, err)
		}

		for _, ipc := range c.TmpResult.IPs {
			// Delete the route that was automatically added
			route := netlink.Route{
				LinkIndex: contVeth.Attrs().Index,
				Dst: &net.IPNet{
					IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
					Mask: ipc.Address.Mask,
				},
				Scope: netlink.SCOPE_NOWHERE,
			}

			if err := c.Link.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete route %v: %v", route, err)
			}

			addrBits := 128
			if ipc.Address.IP.To4() != nil {
				addrBits = 32
			}

			for _, r := range []netlink.Route{
				{
					LinkIndex: contVeth.Attrs().Index,
					Dst: &net.IPNet{
						IP:   ipc.Gateway,
						Mask: net.CIDRMask(addrBits, addrBits),
					},
					Scope: netlink.SCOPE_LINK,
					Src:   ipc.Address.IP,
				},
				{
					LinkIndex: contVeth.Attrs().Index,
					Dst: &net.IPNet{
						IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
						Mask: ipc.Address.Mask,
					},
					Scope: netlink.SCOPE_UNIVERSE,
					Gw:    ipc.Gateway,
					Src:   ipc.Address.IP,
				},
			} {
				if err := c.Link.RouteAdd(&r); err != nil {
					return fmt.Errorf("failed to add route %v: %v", r, err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return hostInterface, containerInterface, nil
}

func (c *EgressContext) setupHostVethv4(vethName string) error {
	// hostVeth moved namespaces and may have a new ifindex
	veth, err := c.Link.LinkByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", vethName, err)
	}

	for _, ipc := range c.TmpResult.IPs {
		maskLen := 128
		if ipc.Address.IP.To4() != nil {
			maskLen = 32
		}

		// NB: this is modified from standard ptp plugin.

		ipn := &net.IPNet{
			IP:   ipc.Gateway,
			Mask: net.CIDRMask(maskLen, maskLen),
		}
		addr := &netlink.Addr{
			IPNet: ipn,
			Scope: int(netlink.SCOPE_LINK), // <- ptp uses SCOPE_UNIVERSE here
		}
		if err = c.Link.AddrAdd(veth, addr); err != nil {
			return fmt.Errorf("failed to add IP addr (%#v) to veth: %v", ipn, err)
		}

		ipn = &net.IPNet{
			IP:   ipc.Address.IP,
			Mask: net.CIDRMask(maskLen, maskLen),
		}
		err := c.Link.RouteAdd(&netlink.Route{
			LinkIndex: veth.Attrs().Index,
			Scope:     netlink.SCOPE_LINK, // <- ptp uses SCOPE_HOST here
			Dst:       ipn,
		})
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to add route on host: %v", err)
		}
	}

	return nil
}

// CmdAddEgressV4 exec necessary settings to support IPv4 egress traffic in EKS IPv6 cluster
func (c *EgressContext) CmdAddEgressV4() (err error) {
	if c.IPTablesIface == nil {
		if c.IPTablesIface, err = c.IptCreator(iptables.ProtocolIPv4); err != nil {
			c.Log.Error("command iptables not found")
			return err
		}
	}
	if err = cniutils.EnableIpForwarding(c.Procsys, c.TmpResult.IPs); err != nil {
		return fmt.Errorf("could not enable IP forwarding: %v", err)
	}

	// NB: This uses netConf.IfName NOT args.IfName.
	hostInterface, _, err := c.setupContainerVethv4()
	if err != nil {
		c.Log.Debugf("failed to setup container Veth: %v", err)
		return err
	}

	if err = c.setupHostVethv4(hostInterface.Name); err != nil {
		return err
	}

	c.Log.Debugf("Node IP: %s", c.NetConf.NodeIP)
	if c.NetConf.NodeIP != nil {
		for _, ipc := range c.TmpResult.IPs {
			if ipc.Address.IP.To4() != nil {
				// add SNAT chain/rules necessary for the container IPv6 egress traffic
				if err = snat.Add(c.IPTablesIface, c.NetConf.NodeIP, ipc.Address.IP, ipv4MulticastRange, c.Chain, c.Comment, c.NetConf.RandomizeSNAT); err != nil {
					return err
				}
			}
		}
	}

	// Copy interfaces over to result, but not IPs.
	c.Result.Interfaces = append(c.Result.Interfaces, c.TmpResult.Interfaces...)

	// Pass through the previous result
	return types.PrintResult(c.Result, c.NetConf.CNIVersion)
}

// CmdDelEgressV4 exec clear the setting to support IPv4 egress traffic in EKS IPv6 cluster
func (c *EgressContext) CmdDelEgressV4() (err error) {
	var ipnets []*net.IPNet
	if c.IPTablesIface == nil {
		if c.IPTablesIface, err = c.IptCreator(iptables.ProtocolIPv4); err != nil {
			c.Log.Error("command iptables not found")
		}
	}
	if c.NsPath != "" {
		err := c.Ns.WithNetNSPath(c.NsPath, func(hostNS ns.NetNS) error {
			var err error

			// DelLinkByNameAddr function deletes an interface and returns IPs assigned to it but it
			// excludes IPs that are not global unicast addresses (or) private IPs. Will not work for
			// our scenario as we use 169.254.0.0/16 range for v4 IPs.

			//Get the interface we want to delete
			iface, err := c.Link.LinkByName(c.NetConf.IfName)

			if err != nil {
				if _, ok := err.(netlink.LinkNotFoundError); ok {
					return nil
				}
				return nil
			}

			//Retrieve IP addresses assigned to the interface
			addrs, err := c.Link.AddrList(iface, netlink.FAMILY_V4)
			if err != nil {
				return fmt.Errorf("failed to get IP addresses for %q: %v", c.NetConf.IfName, err)
			}

			//Delete the interface/link.
			if err = c.Link.LinkDel(iface); err != nil {
				return fmt.Errorf("failed to delete %q: %v", c.NetConf.IfName, err)
			}

			for _, addr := range addrs {
				ipnets = append(ipnets, addr.IPNet)
			}

			if err != nil && err == ip.ErrLinkNotFound {
				c.Log.Debugf("DEL: Link Not Found, returning", err)
				return nil
			}
			return err
		})

		//DEL should be best-effort. We should clean up as much as we can and avoid returning error
		if err != nil {
			c.Log.Debugf("DEL: Executing in container ns errored out, returning", err)
		}
	}

	if c.NetConf.NodeIP != nil {
		c.Log.Debugf("DEL: SNAT setup, let's clean them up. Size of ipnets: %d", len(ipnets))
		for _, ipn := range ipnets {
			if err := snat.Del(c.IPTablesIface, ipn.IP, c.Chain, c.Comment); err != nil {
				return err
			}
		}
	}

	return nil
}

// CmdAddEgressV6 exec necessary settings to support IPv6 egress traffic in EKS IPv4 cluster
func (c *EgressContext) CmdAddEgressV6() (err error) {
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

	if c.IPTablesIface == nil {
		if c.IPTablesIface, err = c.IptCreator(iptables.ProtocolIPv6); err != nil {
			c.Log.Error("command ipv6tables not found")
			return err
		}
	}
	// first disable IPv6 on container's primary interface (eth0)
	err = c.disableInterfaceIPv6()
	if err != nil {
		c.Log.Errorf("failed to disable IPv6 on container interface %s", c.ArgsIfName)
		return err
	}

	hostInterface, containerInterface, err := c.setupContainerVethIPv6()
	if err != nil {
		c.Log.Errorf("veth created failed, ns: %s name: %s, mtu: %d, ipam-result: %+v err: %v",
			c.NsPath, c.NetConf.IfName, c.Mtu, *c.TmpResult, err)
		return err
	}
	c.Log.Debugf("veth pair created for container IPv6 egress traffic, container interface: %s ,host interface: %s",
		containerInterface.Name, hostInterface.Name)

	containerIPv6, err := c.getContainerIpv6GlobalAddrs(containerInterface.Name)
	if err != nil {
		return err
	}
	if len(containerIPv6) > 1 {
		c.Log.Warnf("more than one IPv6 global unicast address found, ifName: %s, IPs: %s", containerInterface.Name, containerIPv6)
	} else if len(containerIPv6) < 1 {
		c.Log.Errorf("no IPv6 global unicast address found, ifName: %s, IPs: %s", containerInterface.Name, containerIPv6)
		return fmt.Errorf("no IPv6 global unicast address found, ifName: %s, IPs: %s", containerInterface.Name, containerIPv6)
	}
	err = c.setupContainerIPv6Route(hostInterface, containerInterface)
	if err != nil {
		c.Log.Errorf("setupContainerIPv6Route failed: %v", err)
		return err
	}
	c.Log.Debugf("container route set up successfully")

	err = c.setupHostIPv6Route(hostInterface, containerIPv6[0])
	if err != nil {
		c.Log.Errorf("setupHostIPv6Route failed: %v", err)
		return err
	}
	c.Log.Debugf("host IPv6 route set up successfully")

	// set up SNAT in host for container IPv6 egress traffic
	// following line adds an ip6tables entries to NAT from pod IPv6 address to node IPv6 address assigned to primary ENI
	err = snat.Add(c.IPTablesIface, c.NetConf.NodeIP, containerIPv6[0], ipv6MulticastRange, c.Chain, c.Comment, c.NetConf.RandomizeSNAT)
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
func (c *EgressContext) CmdDelEgressV6() (err error) {
	var contIPAddrs []netlink.Addr

	if c.IPTablesIface == nil {
		if c.IPTablesIface, err = c.IptCreator(iptables.ProtocolIPv6); err != nil {
			c.Log.Error("command ipv6tables not found")
		}
	}

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
		err = snat.Del(c.IPTablesIface, contIPAddr.IP, c.Chain, c.Comment)
		if err != nil {
			c.Log.Errorf("Delete host SNAT for container IPv6 %s failed: %v.", contIPAddr.IP.String(), err)
		}
		c.Log.Debugf("Successfully deleted SNAT chain/rule for container IPv6 egress traffic: %s", contIPAddr.IP.String())
	}

	return nil
}

func (c *EgressContext) disableInterfaceIPv6() error {
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

func (c *EgressContext) getContainerIpv6GlobalAddrs(ifName string) (containerIPv6 []net.IP, err error) {
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

func (c *EgressContext) setupContainerIPv6Route(hostInterface, containerInterface *current.Interface) (err error) {
	var hostIfIPv6 net.IP
	var hostNetIf netlink.Link
	var addrs []netlink.Addr
	hostNetIf, err = c.Link.LinkByName(hostInterface.Name)
	if err != nil {
		return err
	}
	addrs, err = c.Link.AddrList(hostNetIf, netlink.FAMILY_V6)
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

	return c.Ns.WithNetNSPath(c.NsPath, func(hostNS ns.NetNS) error {
		var containerVethIf netlink.Link
		containerVethIf, err = c.Link.LinkByName(containerInterface.Name)
		if err != nil {
			return err
		}
		// set up from container off-cluster IPv6 route (egress)
		// all from container IPv6 traffic via host veth interface's link-local IPv6 address
		if err := c.Link.RouteReplace(&netlink.Route{
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

// setupHostIPv6Route adds a IPv6 route for traffic destined to container/pod from external/off-cluster
func (c *EgressContext) setupHostIPv6Route(hostInterface *current.Interface, containerIPv6 net.IP) error {
	link := c.Link
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

func (c *EgressContext) setupContainerVethIPv6() (hostInterface, containerInterface *current.Interface, err error) {
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

func (c *EgressContext) hostLocalIpamAdd(stdinData []byte) (err error) {
	var ipamResultI types.Result
	if ipamResultI, err = c.Ipam.ExecAdd(c.NetConf.IPAM.Type, stdinData); err != nil {
		return fmt.Errorf("running IPAM plugin failed: %v", err)
	}

	if c.TmpResult, err = current.NewResultFromResult(ipamResultI); err != nil {
		return err
	}

	if len(c.TmpResult.IPs) == 0 {
		return fmt.Errorf("IPAM plugin returned zero IPs")
	}
	return nil
}
