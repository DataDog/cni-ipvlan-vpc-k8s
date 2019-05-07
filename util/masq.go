// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"fmt"
	"net"

	"github.com/coreos/go-iptables/iptables"
)

// SetupIPMasq installs iptables rules to masquerade traffic
// coming from ipn and going outside of it
func SetupIPMasq(ipn *net.IPNet, oif string, chain string, comment string) error {
	isV6 := ipn.IP.To4() == nil

	var ipt *iptables.IPTables
	var err error
	var multicastNet string

	if isV6 {
		ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		multicastNet = "ff00::/8"
	} else {
		ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
		multicastNet = "224.0.0.0/4"
	}
	if err != nil {
		return fmt.Errorf("failed to locate iptables: %v", err)
	}

	// Create chain if doesn't exist
	exists := false
	chains, err := ipt.ListChains("nat")
	if err != nil {
		return fmt.Errorf("failed to list chains: %v", err)
	}
	for _, ch := range chains {
		if ch == chain {
			exists = true
			break
		}
	}
	if !exists {
		if err = ipt.NewChain("nat", chain); err != nil {
			return err
		}
	}

	// Packets to this network should not be touched
	if err := ipt.AppendUnique("nat", chain, "-d", ipn.String(), "-o", oif, "-j", "ACCEPT", "-m", "comment", "--comment", comment); err != nil {
		return err
	}

	// Don't masquerade multicast - pods should be able to talk to other pods
	// on the local network via multicast.
	if err := ipt.AppendUnique("nat", chain, "!", "-d", multicastNet, "-o", oif, "-j", "MASQUERADE", "-m", "comment", "--comment", comment); err != nil {
		return err
	}

	return ipt.AppendUnique("nat", "POSTROUTING", "-s", ipn.String(), "-o", oif, "-j", chain, "-m", "comment", "--comment", comment)
}

// TeardownIPMasq undoes the effects of SetupIPMasq
func TeardownIPMasq(ipn *net.IPNet, oif string, chain string, comment string) error {
	isV6 := ipn.IP.To4() == nil

	var ipt *iptables.IPTables
	var err error

	if isV6 {
		ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	} else {
		ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	}
	if err != nil {
		return fmt.Errorf("failed to locate iptables: %v", err)
	}

	err = ipt.Delete("nat", "POSTROUTING", "-s", ipn.String(), "-o", oif, "-j", chain, "-m", "comment", "--comment", comment)
	if err != nil && !isNotExist(err) {
		return err
	}

	err = ipt.ClearChain("nat", chain)
	if err != nil && !isNotExist(err) {
		return err

	}

	err = ipt.DeleteChain("nat", chain)
	if err != nil && !isNotExist(err) {
		return err
	}

	return nil
}

// isNotExist returnst true if the error is from iptables indicating
// that the target does not exist.
func isNotExist(err error) bool {
	e, ok := err.(*iptables.Error)
	if !ok {
		return false
	}
	return e.IsNotExist()
}