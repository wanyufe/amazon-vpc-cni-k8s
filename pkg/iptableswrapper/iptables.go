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

// Package iptableswrapper is a wrapper interface for the iptables package
package iptableswrapper

import "github.com/coreos/go-iptables/iptables"

// IptablesIface for unit testing iptables
type IptablesIface interface {
	Exists(table, chain string, rulespec ...string) (bool, error)
	Insert(table, chain string, pos int, rulespec ...string) error
	Append(table, chain string, rulespec ...string) error
	AppendUnique(table, chain string, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	List(table, chain string) ([]string, error)
	NewChain(table, chain string) error
	ClearChain(table, chain string) error
	DeleteChain(table, chain string) error
	ListChains(table string) ([]string, error)
	HasRandomFully() bool
}

type IpTables struct {
	ipt *iptables.IPTables
}

func NewIptables(protocol iptables.Protocol) (IptablesIface, error) {
	ipt, err := iptables.NewWithProtocol(protocol)
	if err != nil {
		return nil, err
	}
	return &IpTables{
		ipt: ipt,
	}, nil
}
func (i IpTables) Exists(table, chain string, rulespec ...string) (bool, error) {
	return i.ipt.Exists(table, chain, rulespec...)
}

func (i IpTables) Insert(table, chain string, pos int, rulespec ...string) error {
	return i.ipt.Insert(table, chain, pos, rulespec...)
}

func (i IpTables) Append(table, chain string, rulespec ...string) error {
	return i.ipt.Append(table, chain, rulespec...)
}

func (i IpTables) AppendUnique(table, chain string, rulespec ...string) error {
	return i.ipt.AppendUnique(table, chain, rulespec...)
}

func (i IpTables) Delete(table, chain string, rulespec ...string) error {
	return i.ipt.Delete(table, chain, rulespec...)
}

func (i IpTables) List(table, chain string) ([]string, error) {
	return i.ipt.List(table, chain)
}

func (i IpTables) NewChain(table, chain string) error {
	return i.ipt.NewChain(table, chain)
}

func (i IpTables) ClearChain(table, chain string) error {
	return i.ipt.ClearChain(table, chain)
}

func (i IpTables) DeleteChain(table, chain string) error {
	return i.ipt.DeleteChain(table, chain)
}

func (i IpTables) ListChains(table string) ([]string, error) {
	return i.ipt.ListChains(table)
}

func (i IpTables) HasRandomFully() bool {
	return i.ipt.HasRandomFully()
}
