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
	"runtime"
	"strconv"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/iptableswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/vethwrapper"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/hostipamwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper"

	"github.com/coreos/go-iptables/iptables"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniversion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/utils"
)

var version string

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func main() {
	skel.PluginMain(cmdAdd, nil, cmdDel, cniversion.All, fmt.Sprintf("egress CNI plugin %s", version))
}

func cmdAdd(args *skel.CmdArgs) (err error) {
	iptCreator := func(protocol iptables.Protocol) (iptableswrapper.IPTablesIface, error) {
		return iptableswrapper.NewIPTables(protocol)
	}
	c := &EgressContext{
		Procsys:    procsyswrapper.NewProcSys(),
		Ns:         nswrapper.NewNS(),
		NsPath:     args.Netns,
		ArgsIfName: args.IfName,
		Ipam:       hostipamwrapper.NewIpam(),
		Link:       netlinkwrapper.NewNetLink(),
		Veth:       vethwrapper.NewSetupVeth(),
		IptCreator: iptCreator,
	}

	return _cmdAdd(args, c)
}

func _cmdAdd(args *skel.CmdArgs, c *EgressContext) (err error) {
	c.NetConf, c.Log, err = LoadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}
	if c.NetConf.PrevResult == nil {
		c.Log.Debugf("must be called as a chained plugin")
		return fmt.Errorf("must be called as a chained plugin")
	}

	c.Result, err = current.GetResult(c.NetConf.PrevResult)
	if err != nil {
		c.Log.Errorf("failed to get PrevResult: %v", err)
		return err
	}
	// Convert MTU from string to int
	c.Mtu, err = strconv.Atoi(c.NetConf.MTU)
	if err != nil {
		c.Log.Errorf("failed to parse MTU: %s, err: %v", c.NetConf.MTU, err)
		return err
	}

	c.Log.Debugf("Received an ADD request for: conf=%v; Plugin enabled=%s", c.NetConf, c.NetConf.Enabled)
	// We will not be vending out this as a separate plugin by itself, and it is only intended to be used as a
	// chained plugin to VPC CNI. We only need this plugin to kick in if egress is enabled in VPC CNI. So, the
	// value of an env variable in VPC CNI determines whether this plugin should be enabled and this is an attempt to
	// pass through the variable configured in VPC CNI.
	if c.NetConf.Enabled != "true" {
		return types.PrintResult(c.Result, c.NetConf.CNIVersion)
	}

	if c.IpTablesIface == nil {
		if c.IpTablesIface, err = c.IptCreator(iptables.ProtocolIPv4); err != nil {
			c.Log.Error("command iptables not found")
			return err
		}
	}

	c.Chain = utils.MustFormatChainNameWithPrefix(c.NetConf.Name, args.ContainerID, "E4-")
	c.Comment = utils.FormatComment(c.NetConf.Name, args.ContainerID)

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			c.Ipam.ExecDel(c.NetConf.IPAM.Type, args.StdinData)
		}
	}()

	var ipamResultI types.Result
	if ipamResultI, err = c.Ipam.ExecAdd(c.NetConf.IPAM.Type, args.StdinData); err != nil {
		return fmt.Errorf("running IPAM plugin failed: %v", err)
	}

	if c.TmpResult, err = current.NewResultFromResult(ipamResultI); err != nil {
		return err
	}

	if len(c.TmpResult.IPs) == 0 {
		err = fmt.Errorf("IPAM plugin returned zero IPs")
		return err
	}

	// IPv4 egress
	c.NetConf.IfName = EgressIPv4InterfaceName
	// explicitly set err var so that above defer function can call ipam.ExecDel
	err = c.CmdAddEgressV4()
	return err
}

func cmdDel(args *skel.CmdArgs) (err error) {
	iptCreator := func(protocol iptables.Protocol) (iptableswrapper.IPTablesIface, error) {
		return iptableswrapper.NewIPTables(protocol)
	}
	c := &EgressContext{
		Ns:         nswrapper.NewNS(),
		NsPath:     args.Netns,
		Ipam:       hostipamwrapper.NewIpam(),
		Link:       netlinkwrapper.NewNetLink(),
		IptCreator: iptCreator,
	}

	return _cmdDel(args, c)
}

func _cmdDel(args *skel.CmdArgs, c *EgressContext) (err error) {
	c.NetConf, c.Log, err = LoadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// We only need this plugin to kick in if egress is enabled
	if c.NetConf.Enabled != "true" {
		c.Log.Debugf("egress-cni plugin is disabled")
		return nil
	}
	c.Log.Debugf("Received Del Request: nsPath: %s conf=%v", c.NsPath, c.NetConf)

	if c.IpTablesIface == nil {
		if c.IpTablesIface, err = c.IptCreator(iptables.ProtocolIPv4); err != nil {
			c.Log.Error("command iptables not found")
		}
	}

	if err = c.Ipam.ExecDel(c.NetConf.IPAM.Type, args.StdinData); err != nil {
		c.Log.Debugf("running IPAM plugin failed: %v", err)
		return fmt.Errorf("running IPAM plugin failed: %v", err)
	}

	c.Chain = utils.MustFormatChainNameWithPrefix(c.NetConf.Name, args.ContainerID, "E4-")
	c.Comment = utils.FormatComment(c.NetConf.Name, args.ContainerID)

	// IPv4 egress
	c.NetConf.IfName = EgressIPv4InterfaceName
	return c.CmdDelEgressV4()
}
