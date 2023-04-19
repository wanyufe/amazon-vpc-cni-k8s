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

	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/share"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/iptableswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/vethwrapper"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/ipamwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/nswrapper"
	"github.com/aws/amazon-vpc-cni-k8s/pkg/procsyswrapper"

	"github.com/coreos/go-iptables/iptables"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	cniversion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/utils"

	"github.com/aws/amazon-vpc-cni-k8s/cmd/egress-cni-plugin/cni"
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

func cmdAdd(args *skel.CmdArgs) error {
	context := &share.Context{
		Procsys:    procsyswrapper.NewProcSys(),
		Ns:         nswrapper.NewNS(),
		NsPath:     args.Netns,
		ArgsIfName: args.IfName,
		Ipam:       ipamwrapper.NewIpam(),
		Link:       netlinkwrapper.NewNetLink(),
		Veth:       vethwrapper.NewSetupVeth(),
	}

	iptv4, err := iptableswrapper.NewIptables(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	iptv6, err := iptableswrapper.NewIptables(iptables.ProtocolIPv6)
	if err != nil {
		return err
	}

	context.Iptv4 = iptv4
	context.Iptv6 = iptv6

	return _cmdAdd(args, context)
}

func _cmdAdd(args *skel.CmdArgs, context *share.Context) (err error) {
	context.NetConf, context.Log, err = share.LoadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}
	if context.NetConf.PrevResult == nil {
		context.Log.Debugf("must be called as a chained plugin")
		return fmt.Errorf("must be called as a chained plugin")
	}

	context.Result, err = current.GetResult(context.NetConf.PrevResult)
	if err != nil {
		context.Log.Errorf("failed to get PrevResult: %v", err)
		return err
	}
	// Convert MTU from string to int
	context.Mtu, err = strconv.Atoi(context.NetConf.MTU)
	if err != nil {
		context.Log.Errorf("failed to parse MTU: %s, err: %v", context.NetConf.MTU, err)
		return err
	}

	context.Log.Debugf("Received an ADD request for: conf=%v; Plugin enabled=%s", context.NetConf, context.NetConf.Enabled)
	// We will not be vending out this as a separate plugin by itself, and it is only intended to be used as a
	// chained plugin to VPC CNI. We only need this plugin to kick in if egress is enabled in VPC CNI. So, the
	// value of an env variable in VPC CNI determines whether this plugin should be enabled and this is an attempt to
	// pass through the variable configured in VPC CNI.
	if context.NetConf.Enabled != "true" {
		return types.PrintResult(context.Result, context.NetConf.CNIVersion)
	}

	isIPv6Egress := context.NetConf.NodeIP.To4() == nil
	var chainPrefix string
	if isIPv6Egress {
		if context.NetConf.NodeIP == nil || !context.NetConf.NodeIP.IsGlobalUnicast() {
			return fmt.Errorf("global unicast IPv6 not found in host primary interface which is mandatory to support IPv6 egress")
		}
		chainPrefix = "E6-"
	} else {
		chainPrefix = "E4-"
	}

	context.Chain = utils.MustFormatChainNameWithPrefix(context.NetConf.Name, args.ContainerID, chainPrefix)
	context.Comment = utils.FormatComment(context.NetConf.Name, args.ContainerID)

	ipamResultI, err := context.Ipam.ExecAdd(context.NetConf.IPAM.Type, args.StdinData)
	if err != nil {
		return fmt.Errorf("running IPAM plugin failed: %v", err)
	}

	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			context.Ipam.ExecDel(context.NetConf.IPAM.Type, args.StdinData)
		}
	}()

	context.TmpResult, err = current.NewResultFromResult(ipamResultI)
	if err != nil {
		return err
	}

	if len(context.TmpResult.IPs) == 0 {
		return fmt.Errorf("IPAM plugin returned zero IPs")
	}

	if isIPv6Egress {
		// IPv6 egress
		context.NetConf.IfName = share.EgressIPv6InterfaceName
		err = cni.CmdAddEgressV6(context)
	} else {
		// IPv4 egress
		context.NetConf.IfName = share.EgressIPv4InterfaceName
		err = cni.CmdAddEgressV4(context)
	}
	return err
}

func cmdDel(args *skel.CmdArgs) (err error) {
	context := &share.Context{
		Ns:     nswrapper.NewNS(),
		NsPath: args.Netns,
		Ipam:   ipamwrapper.NewIpam(),
		Link:   netlinkwrapper.NewNetLink(),
	}

	iptv4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	iptv6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return err
	}

	context.Iptv4 = iptv4
	context.Iptv6 = iptv6

	return _cmdDel(args, context)
}

func _cmdDel(args *skel.CmdArgs, context *share.Context) (err error) {
	context.NetConf, context.Log, err = share.LoadConf(args.StdinData)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// We only need this plugin to kick in if egress is enabled
	if context.NetConf.Enabled != "true" {
		context.Log.Debugf("egress-cni plugin is disabled")
		return nil
	}
	context.Log.Debugf("Received Del Request: nsPath: %s conf=%v", context.NsPath, context.NetConf)

	if err = context.Ipam.ExecDel(context.NetConf.IPAM.Type, args.StdinData); err != nil {
		context.Log.Debugf("running IPAM plugin failed: %v", err)
		return fmt.Errorf("running IPAM plugin failed: %v", err)
	}

	isIPv6Egress := context.NetConf.NodeIP.To4() == nil
	var chainPrefix string
	if isIPv6Egress {
		chainPrefix = "E6-"
	} else {
		chainPrefix = "E4-"
	}
	context.Chain = utils.MustFormatChainNameWithPrefix(context.NetConf.Name, args.ContainerID, chainPrefix)
	context.Comment = utils.FormatComment(context.NetConf.Name, args.ContainerID)

	if isIPv6Egress {
		// IPv6 egress
		context.NetConf.IfName = share.EgressIPv6InterfaceName
		err = cni.CmdDelEgressV6(context)
	} else {
		// IPv4 egress
		context.NetConf.IfName = share.EgressIPv4InterfaceName
		err = cni.CmdDelEgressV4(context)
	}
	return err
}
