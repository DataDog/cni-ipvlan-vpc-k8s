// Copyright 2017 CNI authors
// Copyright 2017 Lyft Inc.
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
// This is a sample chained plugin that supports multiple CNI versions. It
// parses prevResult according to the cniVersion
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/coreos/go-iptables/iptables"
	"github.com/j-keck/arping"
	"github.com/lyft/cni-ipvlan-vpc-k8s/nl"
	"github.com/lyft/cni-ipvlan-vpc-k8s/util"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

// constants for full jitter backoff in milliseconds, and for nodeport marks
const (
	maxSleep              = 10000 // 10.00s
	baseSleep             = 20    //  0.02
	RPFilterTemplate      = "net.ipv4.conf.%s.rp_filter"
	podRulePriority       = 1024
	mainTableRulePriority = 512
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// PluginConf is whatever you expect your configuration json to be. This is whatever
// is passed in on stdin. Your plugin may wish to expose its functionality via
// runtime args, see CONVENTIONS.md in the CNI spec.
type PluginConf struct {
	types.NetConf

	// This is the previous result, when called in the context of a chained
	// plugin. Because this plugin supports multiple versions, we'll have to
	// parse this in two passes. If your plugin is not chained, this can be
	// removed (though you may wish to error if a non-chainable plugin is
	// chained.
	// If you need to modify the result before returning it, you will need
	// to actually convert it to a concrete versioned struct.
	RawPrevResult *map[string]interface{} `json:"prevResult"`
	PrevResult    *current.Result         `json:"-"`

	IPMasq        bool   `json:"ipMasq"`
	HostInterface string `json:"hostInterface"`
	MTU           int    `json:"mtu"`
	TableStart    int    `json:"routeTableStart"`
	NodePortMark  int    `json:"nodePortMark"`
	NodePorts     string `json:"nodePorts"`
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result.
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(conf.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}
	// End previous result parsing

	if conf.HostInterface == "" {
		// Default to the interface associated with the default ipv4 gateway
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: unix.RT_TABLE_MAIN,
		}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
		if err != nil || len(routes) == 0 {
			return nil, fmt.Errorf("hostInterface not set and unable to get default route")
		}

		link, err := netlink.LinkByIndex(routes[0].LinkIndex)
		if err != nil {
			return nil, fmt.Errorf("hostInterface not set and unable to get link for index %v", routes[0].LinkIndex)
		}
		conf.HostInterface = link.Attrs().Name
	}

	// If the MTU is not set, use the one of the IPAM provided interface
	// If there is none, use the hostInterface
	if conf.MTU == 0 {
		if conf.PrevResult != nil && len(conf.PrevResult.Interfaces) > 0 {
			baseMtu, err := nl.GetMtu(conf.PrevResult.Interfaces[0].Name)
			if err != nil {
				return nil, fmt.Errorf("unable to get MTU for IPAM provided interface: %v", conf.PrevResult.Interfaces[0].Name)
			}
			conf.MTU = baseMtu
		} else {
			baseMtu, err := nl.GetMtu(conf.HostInterface)
			if err != nil {
				return nil, fmt.Errorf("unable to get MTU for hostInterface: %v", conf.HostInterface)
			}
			conf.MTU = baseMtu
		}
	}

	if conf.NodePorts == "" {
		conf.NodePorts = "30000:32767"
	}

	if conf.NodePortMark == 0 {
		conf.NodePortMark = 0x2000
	}

	// start using tables by default at 256
	if conf.TableStart == 0 {
		conf.TableStart = 256
	}

	return &conf, nil
}

func enableForwarding(ipv4 bool, ipv6 bool) error {
	if ipv4 {
		err := ip.EnableIP4Forward()
		if err != nil {
			return fmt.Errorf("Could not enable IPv6 forwarding: %v", err)
		}
	}
	if ipv6 {
		err := ip.EnableIP6Forward()
		if err != nil {
			return fmt.Errorf("Could not enable IPv6 forwarding: %v", err)
		}
	}
	return nil
}

func findFreeTable(start int) (int, error) {
	allocatedTableIDs := make(map[int]bool)
	// combine V4 and V6 tables
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return -1, err
		}
		for _, rule := range rules {
			allocatedTableIDs[rule.Table] = true
		}
	}
	// find first slot that's available for both V4 and V6 usage
	for i := start; i < math.MaxUint32; i++ {
		if !allocatedTableIDs[i] {
			return i, nil
		}
	}
	return -1, fmt.Errorf("failed to find free route table")
}

func addPodRouteTable(IPs []*current.IPConfig, eni *net.Interface, route *types.Route, tableStart int) error {
	table := -1

	// try 10 times to write to an empty table slot
	for i := 0; i < 10 && table == -1; i++ {
		var err error
		// jitter looking for an initial free table slot
		table, err = findFreeTable(tableStart + rand.Intn(1000))
		if err != nil {
			return err
		}

		addrBits := 128
		if route.Dst.IP.To4() != nil {
			addrBits = 32
		}

		// add a link local address for the gateway via the ENI and a default route to it
		for _, r := range []netlink.Route{
			{
				LinkIndex: eni.Index,
				Scope:     netlink.SCOPE_LINK,
				Dst: &net.IPNet{
					IP:   route.GW,
					Mask: net.CIDRMask(addrBits, addrBits),
				},
				Table: table,
			},
			{
				LinkIndex: eni.Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       nil,
				Gw:        route.GW,
				Table:     table,
			},
		} {
			if err := netlink.RouteAdd(&r); err != nil {
				table = -1
				break
			}
		}

		if table == -1 {
			// failed to add routes so sleep and try again on a different table
			wait := time.Duration(rand.Intn(int(math.Min(maxSleep,
				baseSleep*math.Pow(2, float64(i)))))) * time.Millisecond
			fmt.Fprintf(os.Stderr, "route table collision, retrying in %v\n", wait)
			time.Sleep(wait)
		}
	}

	// ensure we have a route table selected
	if table == -1 {
		return fmt.Errorf("failed to add routes to a free table")
	}

	for _, ipc := range IPs {
		addrBits := 128
		if ipc.Address.IP.To4() != nil {
			addrBits = 32
		}

		// add policy rule for traffic from pods
		rule := netlink.NewRule()
		rule.Src = &net.IPNet{
			IP:   ipc.Address.IP,
			Mask: net.CIDRMask(addrBits, addrBits),
		}
		rule.Table = table
		rule.Priority = podRulePriority

		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("failed to add policy rule %v: %v", rule, err)
		}
	}

	return nil
}

func setupNodePortRule(ifName string, nodePorts string, nodePortMark int) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("failed to locate iptables: %v", err)
	}

	// Create iptables rules to ensure that nodeport traffic is marked
	if err := ipt.AppendUnique("mangle", "PREROUTING", "-i", ifName, "-p", "tcp", "--dport", nodePorts, "-j", "CONNMARK", "--set-mark", strconv.Itoa(nodePortMark), "-m", "comment", "--comment", "NodePort Mark"); err != nil {
		return err
	}
	if err := ipt.AppendUnique("mangle", "PREROUTING", "-i", ifName, "-p", "udp", "--dport", nodePorts, "-j", "CONNMARK", "--set-mark", strconv.Itoa(nodePortMark), "-m", "comment", "--comment", "NodePort Mark"); err != nil {
		return err
	}
	if err := ipt.AppendUnique("mangle", "PREROUTING", "-i", "veth+", "-j", "CONNMARK", "--restore-mark", "-m", "comment", "--comment", "NodePort Mark"); err != nil {
		return err
	}

	// Use loose RP filter on host interface (RP filter does not take mark-based rules into account)
	_, err = sysctl.Sysctl(fmt.Sprintf(RPFilterTemplate, ifName), "2")
	if err != nil {
		return fmt.Errorf("failed to set RP filter to loose for interface %q: %v", ifName, err)
	}

	// add policy route for traffic from marked as nodeport
	rule := netlink.NewRule()
	rule.Mark = nodePortMark
	rule.Table = unix.RT_TABLE_MAIN // main table
	rule.Priority = mainTableRulePriority

	exists := false
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("Unable to retrive IP rules %v", err)
	}

	for _, r := range rules {
		if r.Table == rule.Table && r.Mark == rule.Mark && r.Priority == rule.Priority {
			exists = true
			break
		}
	}
	if !exists {
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("failed to add policy rule %v: %v", rule, err)
		}
	}

	return nil
}

func setupContainerVeth(netns ns.NetNS, ifName string, mtu int, hostAddrs []netlink.Addr, pr *current.Result) (*current.Interface, *current.Interface, error) {
	hostInterface := &current.Interface{}
	containerInterface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, contVeth0, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}
		hostInterface.Name = hostVeth.Name
		hostInterface.Mac = hostVeth.HardwareAddr.String()
		containerInterface.Name = contVeth0.Name
		containerInterface.Mac = contVeth0.HardwareAddr.String()
		containerInterface.Sandbox = netns.Path()

		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %v", ifName, err)
		}

		contVeth, err := net.InterfaceByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to look up %q: %v", ifName, err)
		}

		pr.Interfaces = []*current.Interface{hostInterface, containerInterface}

		for _, ipc := range pr.IPs {
			// All addresses apply to the container veth interface
			ipc.Interface = current.Int(1)

			// We can't use ConfigureInterface from the ipam package because we don't need all routes
			addr := &netlink.Addr{IPNet: &ipc.Address, Label: ""}
			if err = netlink.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add IP addr %v to %q: %v", ipc, ifName, err)
			}
			// Delete the route that was automatically added
			route := netlink.Route{
				LinkIndex: contVeth.Index,
				Dst: &net.IPNet{
					IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
					Mask: ipc.Address.Mask,
				},
				Scope: netlink.SCOPE_NOWHERE,
			}

			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete route %v: %v", route, err)
			}
		}

		// add host routes for each dst hostInterface ip on dev contVeth
		for _, ipc := range hostAddrs {
			addrBits := 128
			if ipc.IP.To4() != nil {
				addrBits = 32
			}

			err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: contVeth.Index,
				Scope:     netlink.SCOPE_LINK,
				Dst: &net.IPNet{
					IP:   ipc.IP,
					Mask: net.CIDRMask(addrBits, addrBits),
				},
			})

			if err != nil {
				return fmt.Errorf("failed to add host route dst %v: %v", ipc.IP, err)
			}
		}

		// add a default gateway pointed at the first hostAddr
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: contVeth.Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       nil,
			Gw:        hostAddrs[0].IP,
		})

		// Send a gratuitous arp for all v4 addresses
		for _, ipc := range pr.IPs {
			if ipc.Version == "4" {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return hostInterface, containerInterface, nil
}

func setupHostVeth(vethName string, hostAddrs []netlink.Addr, masq bool, tableStart int, eniName string, result *current.Result) error {
	// no IPs to route
	if len(result.IPs) == 0 {
		return nil
	}

	// lookup by name as interface ids might have changed
	veth, err := net.InterfaceByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", vethName, err)
	}

	// add destination routes to Pod IPs
	for _, ipc := range result.IPs {
		addrBits := 128
		if ipc.Address.IP.To4() != nil {
			addrBits = 32
		}

		err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: veth.Index,
			Scope:     netlink.SCOPE_LINK,
			Dst: &net.IPNet{
				IP:   ipc.Address.IP,
				Mask: net.CIDRMask(addrBits, addrBits),
			},
		})
		if err != nil {
			return fmt.Errorf("failed to add host route dst %v: %v", ipc.Address.IP, err)
		}

		// add policy rule for traffic to local pods (pod to pod in particular)
		rule := netlink.NewRule()
		rule.Dst = &net.IPNet{
			IP:   ipc.Address.IP,
			Mask: net.CIDRMask(addrBits, addrBits),
		}
		rule.Table = unix.RT_TABLE_MAIN
		rule.Priority = mainTableRulePriority
		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("failed to add policy rule %v: %v", rule, err)
		}
	}

	eni, err := net.InterfaceByName(eniName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", eniName, err)
	}
	// add route table for traffic from pod and policy rule
	err = addPodRouteTable(result.IPs, eni, result.Routes[0], tableStart)
	if err != nil {
		return fmt.Errorf("failed to add policy rules: %v", err)
	}

	// Send a gratuitous arp for all borrowed v4 addresses
	for _, ipc := range hostAddrs {
		if ipc.IP.To4() != nil {
			_ = arping.GratuitousArpOverIface(ipc.IP, *veth)
		}
	}

	return nil
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	// This is some sample code to generate the list of container-side IPs.
	// We're casting the prevResult to a 0.3.0 response, which can also include
	// host-side IPs (but doesn't when converted from a 0.2.0 response).
	containerIPs := make([]net.IP, 0, len(conf.PrevResult.IPs))
	if conf.CNIVersion != "0.3.0" {
		for _, ip := range conf.PrevResult.IPs {
			containerIPs = append(containerIPs, ip.Address.IP)
		}
	} else {
		for _, ip := range conf.PrevResult.IPs {
			if ip.Interface == nil {
				continue
			}
			intIdx := *ip.Interface
			// Every IP is indexed in to the interfaces array, with "-1" standing
			// for an unknown interface (which we'll assume to be Container-side
			// Skip all IPs we know belong to an interface with the wrong name.
			if intIdx >= 0 && intIdx < len(conf.PrevResult.Interfaces) && conf.PrevResult.Interfaces[intIdx].Name != args.IfName {
				continue
			}
			containerIPs = append(containerIPs, ip.Address.IP)
		}
	}
	if len(containerIPs) == 0 {
		return fmt.Errorf("got no container IPs")
	}

	iface, err := netlink.LinkByName(conf.HostInterface)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", conf.HostInterface, err)
	}

	hostAddrs, err := netlink.AddrList(iface, netlink.FAMILY_ALL)
	if err != nil || len(hostAddrs) == 0 {
		return fmt.Errorf("failed to get host IP addresses for %q: %v", iface, err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	containerIPV4 := false
	containerIPV6 := false
	for _, ipc := range containerIPs {
		if ipc.To4() != nil {
			containerIPV4 = true
		} else {
			containerIPV6 = true
		}
	}

	// Get ENI from the IPAM plugin before overriding it
	eniName := conf.PrevResult.Interfaces[0].Name

	hostInterface, _, err := setupContainerVeth(netns, args.IfName, conf.MTU, hostAddrs, conf.PrevResult)
	if err != nil {
		return err
	}

	if err = setupHostVeth(hostInterface.Name, hostAddrs, conf.IPMasq, conf.TableStart, eniName, conf.PrevResult); err != nil {
		return err
	}

	if conf.IPMasq {
		err := enableForwarding(containerIPV4, containerIPV6)
		if err != nil {
			return err
		}

		chain := utils.FormatChainName(conf.Name, args.ContainerID)
		comment := utils.FormatComment(conf.Name, args.ContainerID)
		for _, ipc := range containerIPs {
			addrBits := 128
			if ipc.To4() != nil {
				addrBits = 32
			}

			if err = util.SetupIPMasq(&net.IPNet{IP: ipc, Mask: net.CIDRMask(addrBits, addrBits)}, conf.HostInterface, chain, comment); err != nil {
				return err
			}
		}
	}

	if err = setupNodePortRule(conf.HostInterface, conf.NodePorts, conf.NodePortMark); err != nil {
		return err
	}

	// Pass through the result for the next plugin
	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	// If the device isn't there then don't try to clean up IP masq either.
	var ipnets []netlink.Addr
	vethPeerIndex := -1
	_ = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error

		iface, err := netlink.LinkByName(args.IfName)
		if err != nil {
			if err.Error() == "Link not found" {
				return ip.ErrLinkNotFound
			}
			return fmt.Errorf("failed to lookup %q: %v", args.IfName, err)
		}

		ipnets, err = netlink.AddrList(iface, netlink.FAMILY_ALL)
		if err != nil || len(ipnets) == 0 {
			return fmt.Errorf("failed to get IP addresses for %q: %v", args.IfName, err)
		}

		vethIface, err := netlink.LinkByName(args.IfName)
		if err != nil && err != ip.ErrLinkNotFound {
			return err
		}
		vethPeerIndex, _ = netlink.VethPeerIndex(&netlink.Veth{LinkAttrs: *vethIface.Attrs()})
		return nil
	})

	if conf.IPMasq {
		chain := utils.FormatChainName(conf.Name, args.ContainerID)
		comment := utils.FormatComment(conf.Name, args.ContainerID)
		for _, ipn := range ipnets {
			addrBits := 128
			if ipn.IP.To4() != nil {
				addrBits = 32
			}

			_ = util.TeardownIPMasq(&net.IPNet{IP: ipn.IP, Mask: net.CIDRMask(addrBits, addrBits)}, conf.HostInterface, chain, comment)
		}
	}

	for _, ipn := range ipnets {
		family := netlink.FAMILY_V6
		if ipn.IP.To4() != nil {
			family = netlink.FAMILY_V4
		}
		rules, err := netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("failed to list rules: %v", err)
		}

		for _, r := range rules {
			// Delete policy rules for traffic to pods
			if r.Dst != nil && r.Dst.IP.Equal(ipn.IP) {
				if err := netlink.RuleDel(&r); err != nil {
					return fmt.Errorf("failed to delete rule: %v, %v", r, err)
				}
			}
			// Delete policy rules for traffic from pods and clear pod route table
			if r.Src != nil && r.Src.IP.Equal(ipn.IP) {
				routes, err := netlink.RouteListFiltered(family, &netlink.Route{
					Table: r.Table,
				}, netlink.RT_FILTER_TABLE)
				if err != nil {
					return fmt.Errorf("failed list routes for table: %v, %v", r.Table, err)
				}
				for _, rt := range routes {
					if err := netlink.RouteDel(&rt); err != nil {
						return fmt.Errorf("failed to delete route: %v, %v", rt, err)
					}
				}
				if err := netlink.RuleDel(&r); err != nil {
					return fmt.Errorf("failed to delete rule: %v, %v", r, err)
				}
			}
		}
	}

	if vethPeerIndex != -1 {
		link, err := netlink.LinkByIndex(vethPeerIndex)
		if err != nil {
			return nil
		}

		_ = netlink.LinkDel(link)
	}

	return nil
}

func main() {
	rand.Seed(time.Now().UnixNano())
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
