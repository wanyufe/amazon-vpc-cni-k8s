package mock_networkutils

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type MockIptables struct {
	// DataplaneState is a map from table name to chain name to slice of rulespecs
	DataplaneState map[string]map[string][][]string
}

func NewMockIptables() *MockIptables {
	return &MockIptables{DataplaneState: map[string]map[string][][]string{}}
}

func (ipt *MockIptables) Exists(table, chainName string, rulespec ...string) (bool, error) {
	chain := ipt.DataplaneState[table][chainName]
	for _, r := range chain {
		if reflect.DeepEqual(rulespec, r) {
			return true, nil
		}
	}
	return false, nil
}

func (ipt *MockIptables) Insert(table, chain string, pos int, rulespec ...string) error {
	if ipt.DataplaneState[table] == nil {
		ipt.DataplaneState[table] = map[string][][]string{}
	}
	ipt.DataplaneState[table][chain] = append(ipt.DataplaneState[table][chain], rulespec)
	return nil
}

func (ipt *MockIptables) Append(table, chain string, rulespec ...string) error {
	if ipt.DataplaneState[table] == nil {
		ipt.DataplaneState[table] = map[string][][]string{}
	}
	ipt.DataplaneState[table][chain] = append(ipt.DataplaneState[table][chain], rulespec)
	return nil
}

func (ipt *MockIptables) AppendUnique(table, chain string, rulespec ...string) error {
	if ipt.DataplaneState[table] == nil {
		ipt.DataplaneState[table] = map[string][][]string{}
	}
	exists, err := ipt.Exists(table, chain, rulespec...)
	if err != nil {
		return err
	}
	if !exists {
		return ipt.Append(table, chain, rulespec...)
	}
	return nil
}

func (ipt *MockIptables) Delete(table, chainName string, rulespec ...string) error {
	chain := ipt.DataplaneState[table][chainName]
	updatedChain := chain[:0]
	found := false
	for _, r := range chain {
		if !found && reflect.DeepEqual(rulespec, r) {
			found = true
			continue
		}
		updatedChain = append(updatedChain, r)
	}
	if !found {
		return errors.New("not found")
	}
	ipt.DataplaneState[table][chainName] = updatedChain
	return nil
}

func (ipt *MockIptables) List(table, chain string) ([]string, error) {
	var chains []string
	chainContents := ipt.DataplaneState[table][chain]
	for _, ruleSpec := range chainContents {
		sanitizedRuleSpec := []string{"-A", chain}
		for _, item := range ruleSpec {
			if strings.Contains(item, " ") {
				item = fmt.Sprintf("%q", item)
			}
			sanitizedRuleSpec = append(sanitizedRuleSpec, item)
		}
		chains = append(chains, strings.Join(sanitizedRuleSpec, " "))
	}
	return chains, nil

}

func (ipt *MockIptables) NewChain(table, chain string) error {
	return nil
}

func (ipt *MockIptables) ClearChain(table, chain string) error {
	return nil
}

func (ipt *MockIptables) DeleteChain(table, chain string) error {
	return nil
}

func (ipt *MockIptables) ListChains(table string) ([]string, error) {
	var chains []string
	for chain := range ipt.DataplaneState[table] {
		chains = append(chains, chain)
	}
	return chains, nil
}

func (ipt *MockIptables) HasRandomFully() bool {
	// TODO: Work out how to write a test case for this
	return true
}
