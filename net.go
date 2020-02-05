/*
Original work Copyright © 2015 Scott Ware
Modifications Copyright 2019 F5 Networks Inc
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
*/
package bigip

import (
	"encoding/json"
	"fmt"
	k8log "github.com/F5Networks/k8s-bigip-ctlr/pkg/vlogger"
	"os"
	"regexp"
	"strings"
)

// Interfaces contains a list of every interface on the BIG-IP system.
type Interfaces struct {
	Interfaces []Interface `json:"items"`
}

// Interface contains information about each individual interface.
type Interface struct {
	Name              string `json:"name,omitempty"`
	FullPath          string `json:"fullPath,omitempty"`
	Generation        int    `json:"generation,omitempty"`
	Bundle            string `json:"bundle,omitempty"`
	Enabled           bool   `json:"enabled,omitempty"`
	FlowControl       string `json:"flowControl,omitempty"`
	ForceGigabitFiber string `json:"forceGigabitFiber,omitempty"`
	IfIndex           int    `json:"ifIndex,omitempty"`
	LLDPAdmin         string `json:"lldpAdmin,omitempty"`
	LLDPTlvmap        int    `json:"lldpTlvmap,omitempty"`
	MACAddress        string `json:"macAddress,omitempty"`
	MediaActive       string `json:"mediaActive,omitempty"`
	MediaFixed        string `json:"mediaFixed,omitempty"`
	MediaMax          string `json:"mediaMax,omitempty"`
	MediaSFP          string `json:"mediaSfp,omitempty"`
	MTU               int    `json:"mtu,omitempty"`
	PreferPort        string `json:"preferPort,omitempty"`
	SFlow             struct {
		PollInterval       int    `json:"pollInterval,omitempty"`
		PollIntervalGlobal string `json:"pollIntervalGlobal,omitempty"`
	} `json:"sflow,omitempty"`
	STP             string `json:"stp,omitempty"`
	STPAutoEdgePort string `json:"stpAutoEdgePort,omitempty"`
	STPEdgePort     string `json:"stpEdgePort,omitempty"`
	STPLinkType     string `json:"stpLinkType,omitempty"`
}

// SelfIPs contains a list of every self IP on the BIG-IP system.
type SelfIPs struct {
	SelfIPs []SelfIP `json:"items"`
}

// SelfIP contains information about each individual self IP. You can use all of
// these fields when modifying a self IP.
type SelfIP struct {
	Name                  string `json:"name,omitempty"`
	Partition             string `json:"partition,omitempty"`
	FullPath              string `json:"fullPath,omitempty"`
	Generation            int    `json:"generation,omitempty"`
	Address               string `json:"address,omitempty"`
	Floating              string `json:"floating,omitempty"`
	InheritedTrafficGroup string `json:"inheritedTrafficGroup,omitempty"`
	TrafficGroup          string `json:"trafficGroup,omitempty"`
	Unit                  int    `json:"unit,omitempty"`
	Vlan                  string `json:"vlan,omitempty"`
	// AllowService          []string `json:"allowService"`
}

// Trunks contains a list of every trunk on the BIG-IP system.
type Trunks struct {
	Trunks []Trunk `json:"items"`
}

// Trunk contains information about each individual trunk. You can use all of
// these fields when modifying a trunk.
type Trunk struct {
	Name               string   `json:"name,omitempty"`
	FullPath           string   `json:"fullPath,omitempty"`
	Generation         int      `json:"generation,omitempty"`
	Bandwidth          int      `json:"bandwidth,omitempty"`
	MemberCount        int      `json:"cfgMbrCount,omitempty"`
	DistributionHash   string   `json:"distributionHash,omitempty"`
	ID                 int      `json:"id,omitempty"`
	LACP               string   `json:"lacp,omitempty"`
	LACPMode           string   `json:"lacpMode,omitempty"`
	LACPTimeout        string   `json:"lacpTimeout,omitempty"`
	LinkSelectPolicy   string   `json:"linkSelectPolicy,omitempty"`
	MACAddress         string   `json:"macAddress,omitempty"`
	STP                string   `json:"stp,omitempty"`
	Type               string   `json:"type,omitempty"`
	WorkingMemberCount int      `json:"workingMbrCount,omitempty"`
	Interfaces         []string `json:"interfaces,omitempty"`
}

// Vlans contains a list of every VLAN on the BIG-IP system.
type Vlans struct {
	Vlans []Vlan `json:"items"`
}

// Vlan contains information about each individual VLAN. You can use all of
// these fields when modifying a VLAN.
type Vlan struct {
	Name            string `json:"name,omitempty"`
	Partition       string `json:"partition,omitempty"`
	FullPath        string `json:"fullPath,omitempty"`
	Generation      int    `json:"generation,omitempty"`
	AutoLastHop     string `json:"autoLastHop,omitempty"`
	CMPHash         string `json:"cmpHash,omitempty"`
	DAGRoundRobin   string `json:"dagRoundRobin,omitempty"`
	Failsafe        string `json:"failsafe,omitempty"`
	FailsafeAction  string `json:"failsafeAction,omitempty"`
	FailsafeTimeout int    `json:"failsafeTimeout,omitempty"`
	IfIndex         int    `json:"ifIndex,omitempty"`
	Learning        string `json:"learning,omitempty"`
	MTU             int    `json:"mtu,omitempty"`
	SFlow           struct {
		PollInterval       int    `json:"pollInterval,omitempty"`
		PollIntervalGlobal string `json:"pollIntervalGlobal,omitempty"`
		SamplingRate       int    `json:"samplingRate,omitempty"`
		SamplingRateGlobal string `json:"samplingRateGlobal,omitempty"`
	} `json:"sflow,omitempty"`
	SourceChecking string `json:"sourceChecking,omitempty"`
	Tag            int    `json:"tag,omitempty"`
}

// VlanInterfaces contains a list of Interface(s) attached to a VLAN.
type VlanInterfaces struct {
	VlanInterfaces []VlanInterface `json:"items"`
}

// VlanInterface contains fields to be used when adding an interface to a VLAN.
type VlanInterface struct {
	Name     string `json:"name,omitempty"`
	Tagged   bool   `json:"tagged,omitempty"`
	Untagged bool   `json:"untagged,omitempty"`
}

// Routes contains a list of every route on the BIG-IP system.
type Routes struct {
	Routes []Route `json:"items"`
}

// Route contains information about each individual route. You can use all
// of these fields when modifying a route.
type Route struct {
	Name       string `json:"name,omitempty"`
	Partition  string `json:"partition,omitempty"`
	FullPath   string `json:"fullPath,omitempty"`
	Generation int    `json:"generation,omitempty"`
	Gateway    string `json:"gw,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	Network    string `json:"network,omitempty"`
}

// RouteDomains contains a list of every route domain on the BIG-IP system.
type RouteDomains struct {
	RouteDomains []RouteDomain `json:"items"`
}

// RouteDomain contains information about each individual route domain. You can use all
// of these fields when modifying a route domain.
type RouteDomain struct {
	Name       string   `json:"name,omitempty"`
	Partition  string   `json:"partition,omitempty"`
	FullPath   string   `json:"fullPath,omitempty"`
	Generation int      `json:"generation,omitempty"`
	ID         int      `json:"id,omitempty"`
	Strict     string   `json:"strict,omitempty"`
	Vlans      []string `json:"vlans,omitempty"`
}

// Tunnels contains a list of tunnel objects on the BIG-IP system.
type Tunnels struct {
	Tunnels []Tunnel `json:"items"`
}

// Tunnel contains information on the tunnel.
// https://devcentral.f5.com/wiki/iControlREST.APIRef_tm_net_tunnels_tunnel.ashx
type Tunnel struct {
	Name             string `json:"name,omitempty"`
	AppService       string `json:"appService,omitempty"`
	AutoLasthop      string `json:"autoLasthop,omitempty"`
	Description      string `json:"description,omitempty"`
	IdleTimeout      int    `json:"idleTimeout,omitempty"`
	IfIndex          int    `json:"ifIndex,omitempty"`
	Key              int    `json:"key,omitempty"`
	LocalAddress     string `json:"localAddress,omitempty"`
	Mode             string `json:"mode,omitempty"`
	Mtu              int    `json:"mtu,omitempty"`
	Partition        string `json:"partition,omitempty"`
	Profile          string `json:"profile,omitempty"`
	RemoteAddress    string `json:"remoteAddress,omitempty"`
	SecondaryAddress string `json:"secondaryAddress,omitempty"`
	Tos              string `json:"tos,omitempty"`
	TrafficGroup     string `json:"trafficGroup,omitempty"`
	Transparent      string `json:"transparent,omitempty"`
	UsePmtu          string `json:"usePmtu,omitempty"`
}

// Vxlans contains a list of vlxan profiles on the BIG-IP system.
type Vxlans struct {
	Vxlans []Vxlan `json:"items"`
}

// Vxlan is the structure for the VXLAN profile on the bigip.
// https://devcentral.f5.com/wiki/iControlREST.APIRef_tm_net_tunnels_vxlan.ashx
type Vxlan struct {
	Name              string `json:"name,omitempty"`
	AppService        string `json:"appService,omitempty"`
	DefaultsFrom      string `json:"defaultsFrom,omitempty"`
	Description       string `json:"description,omitempty"`
	EncapsulationType string `json:"encapsulationType,omitempty"`
	FloodingType      string `json:"floodingType,omitempty"`
	Partition         string `json:"partition,omitempty"`
	Port              int    `json:"port,omitempty"`
}

const (
	uriNet            = "net"
	uriInterface      = "interface"
	uriSelf           = "self"
	uriTrunk          = "trunk"
	uriTunnels        = "tunnels"
	uriTunnel         = "tunnel"
	uriVxlan          = "vxlan"
	uriVlan           = "vlan"
	uriVlanInterfaces = "interfaces"
	uriRoute          = "route"
	uriRouteDomain    = "route-domain"
	uriArp            = "arp"
	uriFdb            = "fdb"
	uriRecords        = "records"
)

// formatResourceID takes the resource name to
// ensure theres a partition for the Resource ID
func formatResourceID(name string) string {
	// If the name specifies the partition already, then
	// just hand it back.
	regex := regexp.MustCompile(`^~([a-zA-Z0-9-.]+)~`)
	if regex.MatchString(name) {
		return name
	}

	// Otherwise, tack on the Common partition
	// for best practices with the resource_id.
	return "~Common~" + name
}

// Interfaces returns a list of interfaces.
func (b *BigIP) Interfaces() (*Interfaces, error) {
	var interfaces Interfaces
	err, _ := b.getForEntity(&interfaces, uriNet, uriInterface)

	if err != nil {
		return nil, err
	}

	return &interfaces, nil
}

// AddInterfaceToVlan associates the given interface to the specified VLAN.
func (b *BigIP) AddInterfaceToVlan(vlan, iface string, tagged bool) error {
	config := &VlanInterface{}

	config.Name = iface
	if tagged {
		config.Tagged = true
	} else {
		config.Untagged = true
	}

	return b.post(config, uriNet, uriVlan, vlan, uriVlanInterfaces)
}

// GetVlanInterfaces returns a list of interface associated to the specified VLAN.
func (b *BigIP) GetVlanInterfaces(vlan string) (*VlanInterfaces, error) {
	var vlanInterfaces VlanInterfaces
	err, _ := b.getForEntity(&vlanInterfaces, uriNet, uriVlan, vlan, uriVlanInterfaces)
	if err != nil {
		return nil, err
	}

	return &vlanInterfaces, nil
}

// SelfIPs returns a list of self IP's.
func (b *BigIP) SelfIPs() (*SelfIPs, error) {
	var self SelfIPs
	err, _ := b.getForEntity(&self, uriNet, uriSelf)
	if err != nil {
		return nil, err
	}

	return &self, nil
}

// SelfIP returns a named Self IP.
func (b *BigIP) SelfIP(selfip string) (*SelfIP, error) {
	var self SelfIP
	err, _ := b.getForEntity(&self, uriNet, uriSelf, selfip)
	if err != nil {
		return nil, err
	}

	return &self, nil
}

// CreateSelfIP adds a new self IP to the BIG-IP system. For <address>, you
// must include the subnet mask in CIDR notation, i.e.: "10.1.1.1/24".
func (b *BigIP) CreateSelfIP(name, address, vlan string) error {
	config := &SelfIP{
		Name:    name,
		Address: address,
		Vlan:    vlan,
	}

	return b.post(config, uriNet, uriSelf)
}

// DeleteSelfIP removes a self IP.
func (b *BigIP) DeleteSelfIP(name string) error {
	return b.delete(uriNet, uriSelf, name)
}

// ModifySelfIP allows you to change any attribute of a self IP. Fields that
// can be modified are referenced in the SelfIP struct.
func (b *BigIP) ModifySelfIP(name string, config *SelfIP) error {
	return b.put(config, uriNet, uriSelf, name)
}

// Trunks returns a list of trunks.
func (b *BigIP) Trunks() (*Trunks, error) {
	var trunks Trunks
	err, _ := b.getForEntity(&trunks, uriNet, uriTrunk)
	if err != nil {
		return nil, err
	}

	return &trunks, nil
}

// CreateTrunk adds a new trunk to the BIG-IP system. <interfaces> must be
// separated by a comma, i.e.: "1.4, 1.6, 1.8".
func (b *BigIP) CreateTrunk(name, interfaces string, lacp bool) error {
	rawInts := strings.Split(interfaces, ",")
	ints := []string{}

	for _, i := range rawInts {
		ints = append(ints, strings.Trim(i, " "))
	}

	config := &Trunk{
		Name:       name,
		Interfaces: ints,
	}

	if lacp {
		config.LACP = "enabled"
	}

	return b.post(config, uriNet, uriTrunk)
}

// DeleteTrunk removes a trunk.
func (b *BigIP) DeleteTrunk(name string) error {
	return b.delete(uriNet, uriTrunk, name)
}

// ModifyTrunk allows you to change any attribute of a trunk. Fields that
// can be modified are referenced in the Trunk struct.
func (b *BigIP) ModifyTrunk(name string, config *Trunk) error {
	return b.put(config, uriNet, uriTrunk, name)
}

// Vlans returns a list of vlans.
func (b *BigIP) Vlans() (*Vlans, error) {
	var vlans Vlans
	err, _ := b.getForEntity(&vlans, uriNet, uriVlan)

	if err != nil {
		return nil, err
	}

	return &vlans, nil
}

// Vlan returns a named vlan.
func (b *BigIP) Vlan(name string) (*Vlan, error) {
	var vlan Vlan
	err, _ := b.getForEntity(&vlan, uriNet, uriVlan, name)

	if err != nil {
		return nil, err
	}

	return &vlan, nil
}

// CreateVlan adds a new VLAN to the BIG-IP system.
func (b *BigIP) CreateVlan(name string, tag int) error {
	config := &Vlan{
		Name: name,
		Tag:  tag,
	}
	return b.post(config, uriNet, uriVlan)
}

// DeleteVlan removes a vlan.
func (b *BigIP) DeleteVlan(name string) error {
	return b.delete(uriNet, uriVlan, name)
}

// ModifyVlan allows you to change any attribute of a VLAN. Fields that
// can be modified are referenced in the Vlan struct.
func (b *BigIP) ModifyVlan(name string, config *Vlan) error {
	return b.put(config, uriNet, uriVlan, name)
}

// Routes returns a list of routes.
func (b *BigIP) Routes() (*Routes, error) {
	var routes Routes
	err, _ := b.getForEntity(&routes, uriNet, uriRoute)

	if err != nil {
		return nil, err
	}

	return &routes, nil
}

func (b *BigIP) GetRoute(name string) (*Route, error) {
	var route Route
	values := []string{}
	regex := regexp.MustCompile(`^(\/.+\/)?(.+)`)
	match := regex.FindStringSubmatch(name)
	if match[1] == "" {
		values = append(values, "~Common~")
	}
	values = append(values, name)
	// Join the strings into one.
	result := strings.Join(values, "")
	err, ok := b.getForEntity(&route, uriNet, uriRoute, result)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &route, nil
}

// CreateRoute adds a new static route to the BIG-IP system. <dest> must include the
// subnet mask in CIDR notation, i.e.: "10.1.1.0/24".
func (b *BigIP) CreateRoute(name, dest, gateway string) error {
	config := &Route{
		Name:    name,
		Network: dest,
		Gateway: gateway,
	}

	return b.post(config, uriNet, uriRoute)
}

// DeleteRoute removes a static route.
func (b *BigIP) DeleteRoute(name string) error {
	return b.delete(uriNet, uriRoute, name)
}

// ModifyRoute allows you to change any attribute of a static route. Fields that
// can be modified are referenced in the Route struct.
func (b *BigIP) ModifyRoute(name string, config *Route) error {
	return b.put(config, uriNet, uriRoute, name)
}

// RouteDomains returns a list of route domains.
func (b *BigIP) RouteDomains() (*RouteDomains, error) {
	var rd RouteDomains
	err, _ := b.getForEntity(&rd, uriNet, uriRouteDomain)

	if err != nil {
		return nil, err
	}

	return &rd, nil
}

// CreateRouteDomain adds a new route domain to the BIG-IP system. <vlans> must be separated
// by a comma, i.e.: "vlan1010, vlan1020".
func (b *BigIP) CreateRouteDomain(name string, id int, strict bool, vlans string) error {
	strictIsolation := "enabled"
	vlanMembers := []string{}
	rawVlans := strings.Split(vlans, ",")

	for _, v := range rawVlans {
		vlanMembers = append(vlanMembers, strings.Trim(v, " "))
	}

	if !strict {
		strictIsolation = "disabled"
	}

	config := &RouteDomain{
		Name:   name,
		ID:     id,
		Strict: strictIsolation,
		Vlans:  vlanMembers,
	}

	return b.post(config, uriNet, uriRouteDomain)
}

// DeleteRouteDomain removes a route domain.
func (b *BigIP) DeleteRouteDomain(name string) error {
	return b.delete(uriNet, uriRouteDomain, name)
}

// ModifyRouteDomain allows you to change any attribute of a route domain. Fields that
// can be modified are referenced in the RouteDomain struct.
func (b *BigIP) ModifyRouteDomain(name string, config *RouteDomain) error {
	return b.put(config, uriNet, uriRouteDomain, name)
}

// Tunnels returns a list of tunnels.
func (b *BigIP) Tunnels() (*Tunnels, error) {
	var tunnels Tunnels
	err, _ := b.getForEntity(&tunnels, uriNet, uriTunnels, uriTunnel)
	if err != nil {
		return nil, err
	}

	return &tunnels, nil
}

// GetTunnel fetches the tunnel by it's name.
func (b *BigIP) GetTunnel(name string) (*Tunnel, error) {
	var tunnel Tunnel
	result := formatResourceID(name)
	err, ok := b.getForEntity(&tunnel, uriNet, uriTunnels, uriTunnel, result)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &tunnel, nil
}

// AddTunnel adds a new tunnel to the BIG-IP system from a config.
func (b *BigIP) AddTunnel(config *Tunnel) error {
	return b.post(config, uriNet, uriTunnels, uriTunnel)
}

// CreateTunnel adds a new tunnel to the BIG-IP system.
func (b *BigIP) CreateTunnel(name, profile string) error {
	config := &Tunnel{
		Name:    name,
		Profile: profile,
	}

	return b.post(config, uriNet, uriTunnels, uriTunnel)
}

// DeleteTunnel removes a tunnel.
func (b *BigIP) DeleteTunnel(name string) error {
	return b.delete(uriNet, uriTunnels, uriTunnel, name)
}

// ModifyTunnel allows you to change any attribute of a tunnel.
func (b *BigIP) ModifyTunnel(name string, config *Tunnel) error {
	return b.put(config, uriNet, uriTunnels, uriTunnel, name)
}

// Vxlans returns a list of vxlan profiles.
func (b *BigIP) Vxlans() ([]Vxlan, error) {
	var vxlans Vxlans
	err, _ := b.getForEntity(&vxlans, uriNet, uriTunnels, uriVxlan)
	if err != nil {
		return nil, err
	}

	return vxlans.Vxlans, nil
}

// GetVxlan fetches the vxlan profile by it's name.
func (b *BigIP) GetVxlan(name string) (*Vxlan, error) {
	var vxlan Vxlan
	result := formatResourceID(name)
	err, ok := b.getForEntity(&vxlan, uriNet, uriTunnels, uriVxlan, result)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	return &vxlan, nil
}

// AddVxlan adds a new vxlan profile to the BIG-IP system.
func (b *BigIP) AddVxlan(config *Vxlan) error {
	return b.post(config, uriNet, uriTunnels, uriVxlan)
}

// CreateVxlan adds a new vxlan profile to the BIG-IP system.
func (b *BigIP) CreateVxlan(name string) error {
	config := &Vxlan{
		Name: name,
	}

	return b.post(config, uriNet, uriTunnels, uriVxlan)
}

// DeleteVxlan removes a vxlan profile.
func (b *BigIP) DeleteVxlan(name string) error {
	return b.delete(uriNet, uriTunnels, uriVxlan, name)
}

// ModifyVxlan allows you to change any attribute of a vxlan profile.
func (b *BigIP) ModifyVxlan(name string, config *Vxlan) error {
	return b.put(config, uriNet, uriTunnels, uriVxlan, name)
}

// Defines an ARP entry.
type ArpType struct {
	// IpAddress corresponds to the JSON schema field "ipAddress".
	IpAddress string `json:"ipAddress"`

	// MacAddress corresponds to the JSON schema field "macAddress".
	MacAddress string `json:"macAddress"`

	// Partition corresponds to the JSON schema field "partition".
	Partition string `json:"partition"`

	// Name corresponds to the JSON schema field "name".
	Name string `json:"name"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *ArpType) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["ipAddress"]; !ok || v == nil {
		return fmt.Errorf("field ipAddress: required")
	}
	if v, ok := raw["macAddress"]; !ok || v == nil {
		return fmt.Errorf("field macAddress: required")
	}
	if v, ok := raw["name"]; !ok || v == nil {
		return fmt.Errorf("field name: required")
	}
	type Plain ArpType
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = ArpType(plain)
	return nil
}

// ArpTypes contains a list of all static arps on the BIG-IP system.
type ArpTypes struct {
	ArpTypes []ArpType `json:"items"`
}

// RecordTypes contains a list of all fdb entries on the BIG-IP system.
type RecordTypes struct {
	RecordTypes []RecordType `json:"items"`
}

// Defines an FDB tunnel.
type FdbTunnelType struct {
	// Name corresponds to the JSON schema field "name".
	Name string `json:"name"`

	// Records corresponds to the JSON schema field "records".
	//Records interface{} `json:"records"`
	Records []RecordType `json:"records"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *FdbTunnelType) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["name"]; !ok || v == nil {
		return fmt.Errorf("field name: required")
	}
	if v, ok := raw["records"]; !ok || v == nil {
		return fmt.Errorf("field records: required")
	}
	type Plain FdbTunnelType
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = FdbTunnelType(plain)
	return nil
}

type RecordType struct {
	// Endpoint corresponds to the JSON schema field "endpoint".
	Endpoint string `json:"endpoint"`

	// Name of the record (MAC address).
	Name string `json:"name"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *RecordType) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["endpoint"]; !ok || v == nil {
		return fmt.Errorf("field endpoint: required")
	}
	if v, ok := raw["name"]; !ok || v == nil {
		return fmt.Errorf("field name: required")
	}
	type Plain RecordType
	var plain Plain
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	*j = RecordType(plain)
	return nil
}

// The CCCL "Cecil" library allows clients to define services that describe
// NET resources on a managed partition of the BIG-IP.  The managed resources
// are defined in this schema definitions section.
// The structure of the service definition is a collection of lists of
// supported resources.  Initially this is ARPs and FDB tunnel records.
// Where appropriate some basic constraints are defined by the schema; however,
// not all actual constraints can be enforced by the schema.  It is the
// responsibility of the client application to ensure that all dependencies
// among the specified resources are met; otherwise, the service will be deployed
// in a degraded state.
//
type CcclNet struct {
	// List of all ARP resources that should exist
	Arps      []ArpType `json:"arps,omitempty"`
	Name      string    `json:"name,omitempty"`
	Partition string    `json:"partition,omitempty"`
	// List of all FDB tunnel resources that should exist
	FdbTunnels []FdbTunnelType `json:"fdbTunnels,omitempty"`

	// List of user-created FDB tunnel resources to be updated. These are expected to
	// be administratively created beforehand. CCCL will perform updates only on these
	// tunnels, no deletion or creation.
	//
	UserFdbTunnels []FdbTunnelType `json:"userFdbTunnels,omitempty"`
}

func (cn *CcclNet) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	type cccl CcclNet
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v, ok := raw["arps"]; !ok || v == nil {
		return fmt.Errorf("field arps: required")
	}
	if v, ok := raw["partition"]; !ok || v == nil {
		return fmt.Errorf("field partition: required")
	}
	if v, ok := raw["fdbTunnels"]; !ok || v == nil {
		return fmt.Errorf("field fdbTunnels: required")
	}

	if err := json.Unmarshal(b, (*cccl)(cn)); err != nil {
		return err
	}

	return nil
}

// CreateARP adds a new Static ARP Entry to BIG-IP system.
// This func expects ArpType struct as input
// returns error if it fails to push entry,
// return nil in successful post
//func (b *BigIP) CreateARP(config *ArpType) error

func (b *BigIP) CreateARP(config *ArpType) error {
	//config := &ArpType{
	//	Name:       name,
	//	IpAddress:  ipaddress,
	//	MacAddress: macaddress,
	//}

	return b.post(config, uriNet, uriArp)
}

// DeleteArp removes a Static ARP entries created.
func (b *BigIP) DeleteArp(name string) error {
	return b.delete(uriNet, uriArp, name)
}

// ModifyARP allows you to change any attribute of a ARP. Fields that
// can be modified are referenced in the *ArpType struct.
func (b *BigIP) ModifyARP(name string, config *ArpType) error {
	return b.put(config, uriNet, uriArp, name)
}

// GetArps returns a list of StaticARP on BIGIP.
func (b *BigIP) GetArps() (*ArpTypes, error) {
	var va ArpTypes
	err, _ := b.getForEntity(&va, uriNet, uriArp)
	if err != nil {
		return nil, err
	}
	return &va, nil
}

// GetFdb returns a list of Fdb entries on BIGIP.
func (b *BigIP) GetFdb(TunnelName string) (*RecordTypes, error) {
	var va RecordTypes
	err, _ := b.getForEntity(&va, uriNet, uriFdb, uriTunnel, TunnelName, uriRecords)
	if err != nil {
		return nil, err
	}
	return &va, nil
}

//The F5 Common Controller Core Library (CCCL) is an orchestration package
//that provides a declarative API for defining BIG-IP LTM and NET services
//in diverse environments (e.g. Marathon, Kubernetes, OpenStack). The
//API will allow a user to create proxy services by specifying the:
//virtual servers, pools, L7 policy and rules, monitors, arps, or fdbTunnels
//as a service description object.  Each instance of the CCCL is initialized
//with namespace qualifiers to allow it to uniquely identify the resources
//under its control.

func (netobject *CcclNet) F5CloudserviceManager() error {
	ip := os.Getenv("BIGIP_HOST")
	admin := os.Getenv("BIGIP_USER")
	passwd := os.Getenv("BIGIP_PASSWORD")
	//f5 := bigip.NewSession(ip, admin, passwd, nil)
	//NewTokenSession(host)
	tknSession, err := NewTokenSession(ip, "443", admin, passwd, "tmos", nil)
	if err != nil {
		k8log.Errorf("Connection to BIGIP failed with:%v", err)
		return err
	}
	k8log.Debugf("BIGIP Handle:%+v", tknSession)
	err = netobject.CreateArpsRecords(tknSession)
	if err != nil {
		k8log.Errorf("Arp Creation failed with :%v", err)
		return err
	}
	err = netobject.CreateFdbRecords(tknSession)
	if err != nil {
		k8log.Errorf("Fdb Creation failed with :%v", err)
		return err
	}
	return nil
}

//CreateNetObject function used to convert NET json string
//to object, this object contains List of ARP/FDB entries
//which are used to configure BIGIP

func CreateNetObject(jsn string) (*CcclNet, error) {
	cn := &CcclNet{}
	err := cn.UnmarshalJSON([]byte(jsn))
	if err != nil {
		k8log.Errorf("UnmarshalJSON Object failed with :%v", err)
	}
	return cn, nil
}

type arpKeyType struct {
	Name      string `json:"name"`
	IpAddress string `json:"ipAddress"`
	Partition string `json:"partition"`
}
type arpValueType struct {
	MacAddress string `json:"macAddress"`
}
type fdbKeyType struct {
	Name string `json:"name"`
}
type fdbValueType struct {
	Endpoint string `json:"endpoint"`
}

//CreateArpsRecords function configures arp entries
//in bigip after validating against existing entries,
//If the entry present and there is change it will modify,
//If no change it will not perform anything
//for complete new entry it configure new entry on bigip
//and will delete unmatched entries

func (cn *CcclNet) CreateArpsRecords(b *BigIP) error {
	oldArpMap := make(map[arpKeyType]arpValueType)
	newArpMap := make(map[arpKeyType]arpValueType)
	existarps, err := b.GetArps()
	if err != nil {
		k8log.Errorf("Fetching ARP entries from BIGIP failed with:%v", err)
		return err
	}
	k8log.Debugf("New Arp entries to be pushed into BIGIP: %+v", cn.Arps)
	k8log.Debugf("Arp entries Exist on BIGIP: %+v", existarps)
	//log.Debugf("Type of :%v\n", reflect.Indirect(reflect.ValueOf(existarps)).Type())

	for _, v := range existarps.ArpTypes {
		oldArpMap[arpKeyType{v.Name, v.IpAddress, v.Partition}] = arpValueType{v.MacAddress}
	}
	for _, v := range cn.Arps {
		newArpMap[arpKeyType{v.Name, v.IpAddress, cn.Partition}] = arpValueType{v.MacAddress}
	}
	for key, val := range newArpMap {
		if _, ok := oldArpMap[key]; ok {
			if val != oldArpMap[key] {
				k := &ArpType{key.IpAddress, val.MacAddress, key.Partition, key.Name}
				//key.Name = "~" + key.Partition + "~" + key.Name
				k8log.Debugf("Modifying struct :%v", k)
				err := b.ModifyARP(key.Name, k)
				if err != nil {
					k8log.Errorf("Modifying Entry failed with :%v", err)
					return err
				}
			}
			//log.Info("Matched Entry:")
			delete(oldArpMap, key)
		} else {
			k := &ArpType{key.IpAddress, val.MacAddress, key.Partition, key.Name}
			k8log.Debugf("New ARP Entry to be Created: %v", k)
			err := b.CreateARP(k)
			if err != nil {
				k8log.Errorf("Posting Entry failed with :%v", err)
				return err
			}
		}
	}
	for key, _ := range oldArpMap {
		key.Name = "~" + key.Partition + "~" + key.Name
		k8log.Debugf("OldEntry to be deleted %v", key.Name)
		err := b.DeleteArp(key.Name)
		if err != nil {
			k8log.Errorf("Deleting Entry failed with :%v", err)
			return err
		}
	}
	return nil
}

// GetFdb returns a list of Fdb entries on BIGIP.
func (fd *RecordType) GetFdbTunnel(b *BigIP) (*RecordTypes, error) {
	var va RecordTypes
	TunnelName := fd.Name
	err, _ := b.getForEntity(&va, uriNet, uriFdb, uriTunnel, TunnelName, uriRecords)
	if err != nil {
		return nil, err
	}
	return &va, nil
}

//CreateFdbRecords function configures fdb entries
//in bigip after validation against existing entries,
//If the entry present in bigip and if there is change it will modify,
//If no change it will not perform anything
//for complete new entry it configure new entry on bigip
//and will delete unmatched entries
func (cn *CcclNet) CreateFdbRecords(b *BigIP) error {
	oldFdbMap := make(map[fdbKeyType]fdbValueType)
	newFdbMap := make(map[fdbKeyType]fdbValueType)
	var tunnelName string

	for _, v := range cn.FdbTunnels {
		tunnelName = v.Name
		existfdb, err := b.GetFdb(tunnelName)
		//existfdb, err := dataFdb.GetFdbTunnel(v.Name)
		if err != nil {
			k8log.Errorf("Fetching FDB entries from BIGIP failed with:%v", err)
			return err
		}
		k8log.Debugf("Fdb entries Available on BIGIP: %+v", existfdb)
		for _, v := range existfdb.RecordTypes {
			oldFdbMap[fdbKeyType{v.Name}] = fdbValueType{v.Endpoint}
		}
		for _, vv := range v.Records {
			newFdbMap[fdbKeyType{vv.Name}] = fdbValueType{vv.Endpoint}
		}
	}
	for key, val := range newFdbMap {
		if _, ok := oldFdbMap[key]; ok {
			if val != oldFdbMap[key] {
				k := &RecordType{val.Endpoint, key.Name}
				k8log.Debugf("Modifying struct :%v", k)
				err := b.patch(k, uriNet, uriFdb, uriTunnel, tunnelName, uriRecords, k.Name)
				if err != nil {
					k8log.Errorf("Modifying Entry failed with :%v", err)
					return err
				}
			}
			//log.Debug("Matched struct ")
			delete(oldFdbMap, key)
		} else {
			k := &RecordType{val.Endpoint, key.Name}
			k8log.Debugf("New fdbEntry struct :%v", k)
			err := b.post(k, uriNet, uriFdb, uriTunnel, tunnelName, uriRecords)
			if err != nil {
				k8log.Errorf("Posting Entry failed with :%v", err)
				return err
			}
		}
	}
	for key, _ := range oldFdbMap {
		k8log.Debugf("oldFdb Entry to be deleted %v", key.Name)
		err := b.delete(uriNet, uriFdb, uriTunnel, tunnelName, uriRecords, key.Name)
		if err != nil {
			k8log.Errorf("Deleting Entry failed with :%v", err)
			return err
		}
	}
	return nil
}
