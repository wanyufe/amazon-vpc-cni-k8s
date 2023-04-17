package cniutils

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/utils/imds"
)

func FindInterfaceByName(ifaceList []*current.Interface, ifaceName string) (ifaceIndex int, iface *current.Interface, found bool) {
	for ifaceIndex, iface := range ifaceList {
		if iface.Name == ifaceName {
			return ifaceIndex, iface, true
		}
	}
	return 0, nil, false
}

func FindIPConfigsByIfaceIndex(ipConfigs []*current.IPConfig, ifaceIndex int) []*current.IPConfig {
	var matchedIPConfigs []*current.IPConfig
	for _, ipConfig := range ipConfigs {
		if ipConfig.Interface != nil && *ipConfig.Interface == ifaceIndex {
			matchedIPConfigs = append(matchedIPConfigs, ipConfig)
		}
	}
	return matchedIPConfigs
}

// WaitForAddressesToBeStable Implements `SettleAddresses` functionality of the `ip` package.
// waitForAddressesToBeStable waits for all addresses on a link to leave tentative state.
// Will be particularly useful for ipv6, where all addresses need to do DAD.
// If any addresses are still tentative after timeout seconds, then error.
func WaitForAddressesToBeStable(netLink netlinkwrapper.NetLink, ifName string, timeout, waitInterval time.Duration) error {
	link, err := netLink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to retrieve link: %v", err)
	}

	deadline := time.Now().Add(timeout)
	for {
		addrs, err := netLink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("could not list addresses: %v", err)
		}

		ok := true
		for _, addr := range addrs {
			if addr.Flags&(syscall.IFA_F_TENTATIVE|syscall.IFA_F_DADFAILED) > 0 {
				ok = false
				break
			}
		}

		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("link %s still has tentative addresses after %d seconds",
				ifName,
				timeout)
		}

		time.Sleep(waitInterval)
	}
}

// GetHostPrimaryInterfaceName returns host primary interface name, for example, `eth0`
func GetHostPrimaryInterfaceName() (string, error) {
	var hostPrimaryIfName string

	// figure out host primary interface
	primaryMAC, err := imds.GetMetaData("mac")
	if err != nil {
		return "", err
	}

	links, err := netlink.LinkList()
	if err != nil {
		return "", err
	}

	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == primaryMAC {
			hostPrimaryIfName = link.Attrs().Name
			break
		}
	}
	return hostPrimaryIfName, nil
}

// SetIPv6AcceptRa will set {value} to /proc/sys/net/ipv6/conf/{ifName}/accept_ra
// using provided ifName and value
// Possible values are:
//
//	"0" Do not accept Router Advertisements.
//	"1" Accept Router Advertisements if forwarding is disabled.
//	"2" Overrule forwarding behaviour. Accept Router Advertisements even if forwarding is enabled.
//
// NOTE: system default value is "1"
func SetIPv6AcceptRa(ifName string, value string) error {
	var entry = "/proc/sys/net/ipv6/conf/" + ifName + "/accept_ra"

	if content, err := os.ReadFile(entry); err == nil {
		if bytes.Equal(bytes.TrimSpace(content), []byte(value)) {
			return nil
		}
	}
	return os.WriteFile(entry, []byte(value), 0644)
}

// GetNodeMetadata calling node local imds metadata service using provided key
// return either a non-empty value or an error
func GetNodeMetadata(key string) (string, error) {
	var value string
	var err error
	for {
		value, err = imds.GetMetaData(key)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
	}
}

// EnableIpForwarding sets forwarding to 1 for both IPv4 and IPv6 if applicable.
// This func is to have a unit testable version of ip.EnableForward in ipforward_linux.go file
// link: https://github.com/containernetworking/plugins/blob/main/pkg/ip/ipforward_linux.go#L34
func EnableIpForwarding(procSys procsyswrapper.ProcSys, ips []*current.IPConfig) error {
	v4 := false
	v6 := false

	for _, ip := range ips {
		if ip.Version == "4" && !v4 {
			valueV4, err := procSys.Get(ipv4ForwardKey)
			if err != nil {
				return err
			}
			if valueV4 != "1" {
				err = procSys.Set(ipv4ForwardKey, "1")
				if err != nil {
					return err
				}
			}
			v4 = true
		} else if ip.Version == "6" && !v6 {
			valueV6, err := procSys.Get(ipv6ForwardKey)
			if err != nil {
				return err
			}
			if valueV6 != "1" {
				err = procSys.Set(ipv6ForwardKey, "1")
				if err != nil {
					return err
				}
			}
			v6 = true
		}
	}
	return nil
}
