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

// package ipamwrapper is a wrapper method for the ipam package
package ipamwrapper

import (
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	_ipam "github.com/containernetworking/plugins/pkg/ipam"
)

type Ipam interface {
	ExecAdd(plugin string, netconf []byte) (types.Result, error)

	ExecCheck(plugin string, netconf []byte) error

	ExecDel(plugin string, netconf []byte) error

	ConfigureIface(ifName string, res *current.Result) error
}

type ipam struct{}

// NewIpam return a new Ipam object
func NewIpam() Ipam {
	return &ipam{}
}
func (i *ipam) ExecAdd(plugin string, netconf []byte) (types.Result, error) {
	return _ipam.ExecAdd(plugin, netconf)
}

func (i *ipam) ExecCheck(plugin string, netconf []byte) error {
	return _ipam.ExecCheck(plugin, netconf)
}

func (i *ipam) ExecDel(plugin string, netconf []byte) error {
	return _ipam.ExecDel(plugin, netconf)
}

func (i *ipam) ConfigureIface(ifName string, res *current.Result) error {
	return _ipam.ConfigureIface(ifName, res)
}
