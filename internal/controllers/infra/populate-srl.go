/*
Copyright 2021 NDD.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package infra

import (
	"strconv"
	"strings"

	"github.com/openconfig/ygot/ygot"
	"github.com/pkg/errors"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/intent"
	abstractionsrl3v1alpha1 "github.com/yndd/nddp-srl3/pkg/abstraction/srl3/v1alpha1"
	intentsrl3v1alpha1 "github.com/yndd/nddp-srl3/pkg/intent/srl3/v1alpha1"
	"github.com/yndd/nddp-srl3/pkg/ygotsrl"
	ipamv1alpha1 "github.com/yndd/nddr-ipam-registry/apis/ipam/v1alpha1"
)

func (r *application) srlPopulateSchema(cr *infrav1alpha1.Infrastructure, ci *intent.Compositeintent, crName string, nodeInfo []*nodeLinkInfo, idx int) error {
	deviceName := nodeInfo[idx].name
	n := nodeInfo[idx]

	ci.AddChild(deviceName, intentsrl3v1alpha1.InitSrl(r.client, ci, deviceName))
	srld := ci.GetChildData(deviceName)
	d, ok := srld.(*ygotsrl.Device)
	if !ok {
		return errors.New("expected ygot struct")
	}
	r.abstractions[crName].AddChild(deviceName, abstractionsrl3v1alpha1.InitSrl(r.client, deviceName, n.platform))
	a, err := r.abstractions[crName].GetChild(deviceName)
	if err != nil {
		return err
	}
	r.log.Debug("itfceName", "before", n.itfceName)
	if n.itfceName, err = a.GetInterfaceName(n.itfceName); err != nil {
		return err
	}
	r.log.Debug("itfceName", "after", n.itfceName)
	if n.lagName, err = a.GetInterfaceName(n.lagName); err != nil {
		return err
	}
	if err := r.srlPopulateNode(cr, d, n); err != nil {
		return err
	}
	if n.lagMember {
		// create node and link without ip addresses and subinterfaces
		if err := r.srlPopulateLagMember(d, n); err != nil {
			return err
		}
	} else {
		// create node and link with ip addresses and subinterfaces
		// nn is neighbor node info
		var nn *nodeLinkInfo
		if idx == 0 {
			nn = nodeInfo[1]
		} else {
			nn = nodeInfo[0]
		}
		if err := r.srlPopulateIpLink(cr, d, n, nn); err != nil {
			return err
		}
	}
	return nil
}

func (r *application) srlPopulateNode(cr *infrav1alpha1.Infrastructure, d *ygotsrl.Device, n *nodeLinkInfo) error {

	// create a system interface
	i := d.GetOrCreateInterface("system0")
	i.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	i.Description = ygot.String("ndd system interface")

	// create a subinterface
	siIndex := 0
	si := i.GetOrCreateSubinterface(uint32(siIndex))
	si.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	si.Description = ygot.String(strings.Join([]string{"ndd-infra", "system0"}, "-"))
	si.Index = ygot.Uint32(*si.Index)

	// create and irb interface
	irb := d.GetOrCreateInterface("irb0")
	irb.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	irb.Name = ygot.String("irb0")
	irb.Description = ygot.String(strings.Join([]string{"ndd-infra", "irb0"}, "-"))

	// create a vxlan tunnel interface
	ti := d.GetOrCreateTunnelInterface("vxlan0")
	ti.Name = ygot.String("vxlan0")

	// create a routing policy
	rp := d.GetOrCreateRoutingPolicy().GetOrCreatePolicy("export-local")
	rp.Name = ygot.String("export-local")

	// depending on the address family supported add ipv4 system ip, ipv4 route policy
	for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
		switch af {
		case string(ipamv1alpha1.AddressFamilyIpv4):
			si.Ipv4 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4{
				Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4_Address{
					n.systemPrefixIpv4: {
						IpPrefix: ygot.String(n.systemPrefixIpv4),
					},
				},
			}
			polPsIpv4 := d.GetOrCreateRoutingPolicy().GetOrCreatePrefixSet("local-ipv4")
			polPsIpv4Key := ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix_Key{
				IpPrefix:        cr.GetLoopbackCidrIpv4(),
				MaskLengthRange: "32..32",
			}
			polPsIpv4.Prefix = map[ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix_Key]*ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix{
				polPsIpv4Key: {
					IpPrefix:        ygot.String(cr.GetLoopbackCidrIpv4()),
					MaskLengthRange: ygot.String("32..32"),
				},
			}
			rp.Statement = map[uint32]*ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement{
				10: {
					SequenceId: ygot.Uint32(10),
					Match: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Match{
						PrefixSet: ygot.String("local-ipv4"),
					},
					Action: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Action{
						Accept: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Action_Accept{},
					},
				},
			}
		case string(ipamv1alpha1.AddressFamilyIpv6):
			si.Ipv6 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6{
				Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6_Address{
					n.systemPrefixIpv6: {
						IpPrefix: ygot.String(n.systemPrefixIpv6),
					},
				},
			}
			polPsIpv6 := d.GetOrCreateRoutingPolicy().GetOrCreatePrefixSet("local-ipv6")
			polPsIpv6Key := ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix_Key{
				IpPrefix:        cr.GetLoopbackCidrIpv6(),
				MaskLengthRange: "128..128",
			}
			polPsIpv6.Prefix = map[ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix_Key]*ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix{
				polPsIpv6Key: {
					IpPrefix:        ygot.String(cr.GetLoopbackCidrIpv6()),
					MaskLengthRange: ygot.String("128..128"),
				},
			}
			rp.Statement = map[uint32]*ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement{
				20: {
					SequenceId: ygot.Uint32(20),
					Match: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Match{
						PrefixSet: ygot.String("local-ipv6"),
					},
					Action: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Action{
						Accept: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Action_Accept{},
					},
				},
			}
		}
	}

	niName := cr.GetNetworkInstanceName()
	ni := d.GetOrCreateNetworkInstance(niName)
	ni.Description = ygot.String(strings.Join([]string{"ndd-infra", niName}, "-"))
	ni.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	ni.Type = ygotsrl.SrlNokiaNetworkInstance_NiType_default
	ni.Name = ygot.String(niName)

	ni.GetOrCreateInterface("system0.0")

	r.log.Debug("networkinstance default", "added", "system0.0")

	bgp := ni.GetOrCreateProtocols().GetOrCreateBgp()
	bgp.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	bgp.AutonomousSystem = ygot.Uint32(n.as)
	bgp.RouterId = ygot.String(strings.Split(n.systemPrefixIpv4, "/")[0])
	bgp.EbgpDefaultPolicy = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_EbgpDefaultPolicy{
		ExportRejectAll: ygot.Bool(false),
		ImportRejectAll: ygot.Bool(false),
	}
	bgp.Evpn = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Evpn{
		AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
	}
	bgp.Ipv4Unicast = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Ipv4Unicast{
		AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
		Multipath: &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Ipv4Unicast_Multipath{
			AllowMultipleAs: ygot.Bool(true),
			MaxPathsLevel_1: ygot.Uint32(64),
			MaxPathsLevel_2: ygot.Uint32(64),
		},
	}
	bgp.Ipv6Unicast = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Ipv6Unicast{
		AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
		Multipath: &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Ipv6Unicast_Multipath{
			AllowMultipleAs: ygot.Bool(true),
			MaxPathsLevel_1: ygot.Uint32(64),
			MaxPathsLevel_2: ygot.Uint32(64),
		},
	}

	bgpOverlayGroup := bgp.GetOrCreateGroup("overlay")
	bgpOverlayGroup.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	bgpOverlayGroup.Evpn = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Group_Evpn{
		AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
	}

	bgpUnderlayGroup := bgp.GetOrCreateGroup("underlay")
	bgpUnderlayGroup.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	bgpUnderlayGroup.NextHopSelf = ygot.Bool(true)
	bgpUnderlayGroup.ExportPolicy = ygot.String("export-local")
	bgpUnderlayGroup.Ipv4Unicast = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Group_Ipv4Unicast{
		AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
	}
	bgpUnderlayGroup.Ipv6Unicast = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Group_Ipv6Unicast{
		AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
	}
	bgpUnderlayGroup.Evpn = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Group_Evpn{
		AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
	}

	d.GetOrCreateSystem().GetOrCreateNetworkInstance().GetOrCreateProtocols().GetOrCreateBgpVpn().GetOrCreateBgpInstance(1)
	d.GetOrCreateSystem().GetOrCreateNetworkInstance().GetOrCreateProtocols().GetOrCreateEvpn().GetOrCreateEthernetSegments().GetOrCreateBgpInstance(1)
	return nil
}

/*
func (r *application) SrlPopulateNode(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}

	crName := getCrName(mg)
	ci := r.intents[crName]

	// loop over each endpoint of a link
	for idx := 0; idx <= 1; idx++ {
		deviceName, _ := getDeviceItfce(idx, link)

		node := r.newTopoNode()
		if err := r.client.Get(ctx, types.NamespacedName{
			Namespace: mg.GetNamespace(),
			Name:      strings.Join([]string{odns.GetParentResourceName(link.GetName()), deviceName}, "."),
		}, node); err != nil {
			// There's no need to requeue if we no longer exist. Otherwise we'll be
			// requeued implicitly because we return an error.
			//log.Debug("Cannot get managed resource", "error", err)
			return err
		}

		//platform := node.GetPlatform()

		ci.AddChild(deviceName, intentsrl3v1alpha1.InitSrl(r.client, ci, deviceName))
		srld := ci.GetChildData(deviceName)
		d, ok := srld.(*ygotsrl.Device)
		if !ok {
			return errors.New("expected ygot struct")
		}

		fullIdx := getIndex(node.GetNodeIndex(), node.GetPosition())
		var err error

		as, err := getAS(cr, fullIdx)
		if err != nil {
			return err
		}

		var ipv4 *ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4
		var ipv6 *ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6
		var ipv4Prefix *string
		var ipv6Prefix *string
		for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
			switch af {
			case string(ipamv1alpha1.AddressFamilyIpv4):
				ipv4Prefix, err = getLoopbackIpv4(cr, fullIdx)
				if err != nil {
					return err
				}

				ipv4 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4{
					Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4_Address{
						*ipv4Prefix: {
							IpPrefix: ygot.String(*ipv4Prefix),
						},
					},
				}
			case string(ipamv1alpha1.AddressFamilyIpv6):
				ipv6Prefix, err = getLoopbackIpv6(cr, fullIdx)
				if err != nil {
					return err
				}

				ipv6 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6{
					Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6_Address{
						*ipv6Prefix: {
							IpPrefix: ygot.String(*ipv6Prefix),
						},
					},
				}
			}
		}
		i := d.GetOrCreateInterface("system0")
		i.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		i.Description = ygot.String("ndd system interface")

		siIndex := 0
		si := i.GetOrCreateSubinterface(uint32(siIndex))
		si.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		si.Description = ygot.String(strings.Join([]string{"ndd-infra", "irb0"}, "-"))
		si.Index = ygot.Uint32(*si.Index)
		si.Ipv4 = ipv4
		si.Ipv6 = ipv6

		irb := d.GetOrCreateInterface("irb0")
		irb.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		irb.Name = ygot.String("irb0")
		irb.Description = ygot.String(strings.Join([]string{"ndd-infra", "irb0"}, "-"))
		ti := d.GetOrCreateTunnelInterface("vxlan0")
		ti.Name = ygot.String("vxlan0")

		polPsIpv4 := d.GetOrCreateRoutingPolicy().GetOrCreatePrefixSet("local-ipv4")
		polPsIpv4Key := ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix_Key{
			IpPrefix:        cr.GetLoopbackCidrIpv4(),
			MaskLengthRange: "32..32",
		}
		polPsIpv4.Prefix = map[ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix_Key]*ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix{
			polPsIpv4Key: {
				IpPrefix:        ygot.String(cr.GetLoopbackCidrIpv4()),
				MaskLengthRange: ygot.String("32..32"),
			},
		}

		polPsIpv6 := d.GetOrCreateRoutingPolicy().GetOrCreatePrefixSet("local-ipv6")
		polPsIpv6Key := ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix_Key{
			IpPrefix:        cr.GetLoopbackCidrIpv6(),
			MaskLengthRange: "128..128",
		}
		polPsIpv6.Prefix = map[ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix_Key]*ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_PrefixSet_Prefix{
			polPsIpv6Key: {
				IpPrefix:        ygot.String(cr.GetLoopbackCidrIpv6()),
				MaskLengthRange: ygot.String("128..128"),
			},
		}

		rp := d.GetOrCreateRoutingPolicy().GetOrCreatePolicy("export-local")
		rp.Name = ygot.String("export-local")
		rp.Statement = map[uint32]*ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement{
			10: {
				SequenceId: ygot.Uint32(10),
				Match: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Match{
					PrefixSet: ygot.String("local-ipv4"),
				},
				Action: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Action{
					Accept: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Action_Accept{},
				},
			},
			20: {
				SequenceId: ygot.Uint32(20),
				Match: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Match{
					PrefixSet: ygot.String("local-ipv6"),
				},
				Action: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Action{
					Accept: &ygotsrl.SrlNokiaRoutingPolicy_RoutingPolicy_Policy_Statement_Action_Accept{},
				},
			},
		}

		niName := cr.GetNetworkInstanceName()
		ni := d.GetOrCreateNetworkInstance(niName)
		ni.Description = ygot.String(strings.Join([]string{"ndd-infra", niName}, "-"))
		ni.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		ni.Type = ygotsrl.SrlNokiaNetworkInstance_NiType_default
		ni.Name = ygot.String(niName)

		ni.GetOrCreateInterface("system0.0")

		r.log.Debug("networkinstance default", "added", "system0.0")

		bgp := ni.GetOrCreateProtocols().GetOrCreateBgp()
		bgp.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		bgp.AutonomousSystem = ygot.Uint32(*as)
		bgp.RouterId = ygot.String(strings.Split(*ipv4Prefix, "/")[0])
		bgp.EbgpDefaultPolicy = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_EbgpDefaultPolicy{
			ExportRejectAll: ygot.Bool(false),
			ImportRejectAll: ygot.Bool(false),
		}
		bgp.Evpn = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Evpn{
			AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
		}
		bgp.Ipv4Unicast = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Ipv4Unicast{
			AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
			Multipath: &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Ipv4Unicast_Multipath{
				AllowMultipleAs: ygot.Bool(true),
				MaxPathsLevel_1: ygot.Uint32(64),
				MaxPathsLevel_2: ygot.Uint32(64),
			},
		}
		bgp.Ipv6Unicast = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Ipv6Unicast{
			AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
			Multipath: &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Ipv6Unicast_Multipath{
				AllowMultipleAs: ygot.Bool(true),
				MaxPathsLevel_1: ygot.Uint32(64),
				MaxPathsLevel_2: ygot.Uint32(64),
			},
		}

		bgpOverlayGroup := bgp.GetOrCreateGroup("overlay")
		bgpOverlayGroup.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		bgpOverlayGroup.Evpn = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Group_Evpn{
			AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
		}

		bgpUnderlayGroup := bgp.GetOrCreateGroup("underlay")
		bgpUnderlayGroup.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		bgpUnderlayGroup.NextHopSelf = ygot.Bool(true)
		bgpUnderlayGroup.ExportPolicy = ygot.String("export-local")
		bgpUnderlayGroup.Ipv4Unicast = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Group_Ipv4Unicast{
			AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
		}
		bgpUnderlayGroup.Ipv6Unicast = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Group_Ipv6Unicast{
			AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
		}
		bgpUnderlayGroup.Evpn = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Group_Evpn{
			AdminState: ygotsrl.SrlNokiaCommon_AdminState_enable,
		}

		d.GetOrCreateSystem().GetOrCreateNetworkInstance().GetOrCreateProtocols().GetOrCreateBgpVpn().GetOrCreateBgpInstance(1)
		d.GetOrCreateSystem().GetOrCreateNetworkInstance().GetOrCreateProtocols().GetOrCreateEvpn().GetOrCreateEthernetSegments().GetOrCreateBgpInstance(1)
	}
	return nil
}
*/

func (r *application) srlPopulateLagMember(d *ygotsrl.Device, n *nodeLinkInfo) error {
	i := d.GetOrCreateInterface(n.itfceName)
	i.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	i.Description = ygot.String(strings.Join([]string{"infra", n.itfceName}, "-"))
	i.Ethernet = &ygotsrl.SrlNokiaInterfaces_Interface_Ethernet{
		AggregateId: ygot.String(n.lagName),
		PortSpeed:   ygotsrl.SrlNokiaInterfaces_Interface_Ethernet_PortSpeed_100G,
	}
	return nil
}

/*
func (r *application) SrlPopulateLagMember(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	crName := getCrName(mg)
	s := r.intents[crName]

	for idx := 0; idx <= 1; idx++ {
		deviceName, itfceName := getDeviceItfce(idx, link)
		_, lagName := getLagInfo(idx, link)
		if strings.Contains(lagName, "lag") {
			lagName = strings.ReplaceAll(lagName, "-", "")
			lagName = strings.ReplaceAll(lagName, "49", "31")
			lagName = strings.ReplaceAll(lagName, "50", "32")
		}
		if strings.Contains(itfceName, "int-") {
			split := strings.Split(itfceName, "/")
			if len(split) > 2 {
				itfceName = "ethernet-" + split[len(split)-2] + "/" + split[len(split)-1]
			}
		}

		s.AddChild(deviceName, intentsrl3v1alpha1.InitSrl(r.client, s, deviceName))
		srld := s.GetChildData(deviceName)
		d, ok := srld.(*ygotsrl.Device)
		if !ok {
			return errors.New("expected ygot struct")
		}

		i := d.GetOrCreateInterface(itfceName)
		i.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		i.Description = ygot.String("ndd-infra" + itfceName)
		i.Ethernet = &ygotsrl.SrlNokiaInterfaces_Interface_Ethernet{
			AggregateId: ygot.String(lagName),
			PortSpeed:   ygotsrl.SrlNokiaInterfaces_Interface_Ethernet_PortSpeed_100G,
		}
	}
	return nil
}
*/
func (r *application) srlPopulateIpLink(cr *infrav1alpha1.Infrastructure, d *ygotsrl.Device, n, nn *nodeLinkInfo) error {
	i := d.GetOrCreateInterface(n.itfceName)
	i.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	i.Description = ygot.String(strings.Join([]string{"ndd-infra", n.itfceName}, "-"))

	if strings.Contains(n.itfceName, "lag") {
		lagType := ygotsrl.SrlNokiaInterfacesLag_LagType_static
		if n.lacp {
			lagType = ygotsrl.SrlNokiaInterfacesLag_LagType_lacp
		}

		if n.lacpFallBack {
			i.Lag = &ygotsrl.SrlNokiaInterfaces_Interface_Lag{
				Lacp: &ygotsrl.SrlNokiaInterfaces_Interface_Lag_Lacp{
					Interval: ygotsrl.SrlNokiaLacp_LacpPeriodType_SLOW,
					LacpMode: ygotsrl.SrlNokiaLacp_LacpActivityType_ACTIVE,
				},
				LacpFallbackMode: ygotsrl.SrlNokiaInterfacesLag_LacpFallbackType_static,
				LagType:          ygotsrl.SrlNokiaInterfacesLag_LagType_lacp,
				MemberSpeed:      ygotsrl.SrlNokiaInterfacesLag_MemberSpeedType_100G,
			}
		} else {
			i.Lag = &ygotsrl.SrlNokiaInterfaces_Interface_Lag{
				Lacp: &ygotsrl.SrlNokiaInterfaces_Interface_Lag_Lacp{
					Interval: ygotsrl.SrlNokiaLacp_LacpPeriodType_SLOW,
					LacpMode: ygotsrl.SrlNokiaLacp_LacpActivityType_ACTIVE,
				},
				LagType:     lagType,
				MemberSpeed: ygotsrl.SrlNokiaInterfacesLag_MemberSpeedType_100G,
			}
		}
	}

	siIndex := 0

	si := i.GetOrCreateSubinterface(uint32(siIndex))
	si.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
	si.Description = ygot.String(strings.Join([]string{"ndd-infra", n.itfceName}, "-"))

	ni := d.GetOrCreateNetworkInstance("default")
	ni.GetOrCreateInterface(n.itfceName + "." + strconv.Itoa(siIndex))

	r.log.Debug("networkinstance default", "added", n.itfceName+"."+strconv.Itoa(siIndex))

	bgp := ni.GetOrCreateProtocols().GetOrCreateBgp()

	for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
		switch af {
		case string(ipamv1alpha1.AddressFamilyIpv4):
			si.Ipv4 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4{
				Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4_Address{
					n.linkPrefixIpv4: {
						IpPrefix: ygot.String(n.linkPrefixIpv4),
					},
				},
			}
			bgpNeighbor := bgp.GetOrCreateNeighbor(strings.Split(nn.linkPrefixIpv4, "/")[0])
			bgpNeighbor.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
			bgpNeighbor.LocalAs = map[uint32]*ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Neighbor_LocalAs{
				n.as: {
					AsNumber: ygot.Uint32(n.as),
				},
			}
			bgpNeighbor.PeerGroup = ygot.String("underlay")
			bgpNeighbor.PeerAs = ygot.Uint32(nn.as)
			bgpNeighbor.PeerAddress = ygot.String(strings.Split(nn.linkPrefixIpv4, "/")[0])
			bgpNeighbor.Transport = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Neighbor_Transport{
				LocalAddress: ygot.String(strings.Split(n.linkPrefixIpv4, "/")[0]),
			}
		case string(ipamv1alpha1.AddressFamilyIpv6):
			si.Ipv6 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6{
				Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6_Address{
					n.linkPrefixIpv6: {
						IpPrefix: ygot.String(n.linkPrefixIpv6),
					},
				},
			}
			bgpNeighbor := bgp.GetOrCreateNeighbor(strings.Split(nn.linkPrefixIpv6, "/")[0])
			bgpNeighbor.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
			bgpNeighbor.LocalAs = map[uint32]*ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Neighbor_LocalAs{
				n.as: {
					AsNumber: ygot.Uint32(n.as),
				},
			}
			bgpNeighbor.PeerGroup = ygot.String("underlay")
			bgpNeighbor.PeerAs = ygot.Uint32(nn.as)
			bgpNeighbor.PeerAddress = ygot.String(strings.Split(nn.linkPrefixIpv6, "/")[0])
			bgpNeighbor.Transport = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Neighbor_Transport{
				LocalAddress: ygot.String(strings.Split(n.linkPrefixIpv6, "/")[0]),
			}
		}
	}

	return nil
}

/*
func (r *application) SrlPopulateIpLink(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}
	crName := getCrName(mg)
	s := r.intents[crName]

	// get node information
	nodeInfo := make([]*nodeInfo, 2)
	spineIdx := 0
	leafIdx := 0
	for idx := 0; idx <= 1; idx++ {
		deviceName, itfceName := getDeviceItfce(idx, link)

		node := r.newTopoNode()
		if err := r.client.Get(ctx, types.NamespacedName{
			Namespace: mg.GetNamespace(),
			Name:      strings.Join([]string{odns.GetParentResourceName(link.GetName()), deviceName}, "."),
		}, node); err != nil {
			// There's no need to requeue if we no longer exist. Otherwise we'll be
			// requeued implicitly because we return an error.
			//log.Debug("Cannot get managed resource", "error", err)
			return err
		}
		var err error
		nodeInfo[idx], err = getNodeInfo(cr, node, itfceName)
		if err != nil {
			return err
		}
		// TODOD move to pod idx per spine
		if nodeInfo[idx].position == "spine" {
			spineIdx = idx
		}
		if nodeInfo[idx].position == "leaf" {
			leafIdx = idx
		}

	}
	leaf2leaf := false
	if nodeInfo[0].position == "leaf" && nodeInfo[1].position == "leaf" {
		leaf2leaf = true
	}

	var indexA, indexB uint32
	if leaf2leaf {
		indexA = nodeInfo[0].itfceIdx
		indexB = nodeInfo[1].itfceIdx
	} else {
		indexB = nodeInfo[spineIdx].itfceIdx
		indexA = nodeInfo[leafIdx].itfceIdx
	}

	// TODO 169.254.0.0/16
	linkPrefixIpv4A := strings.Join([]string{"100.66", strconv.Itoa(int(indexB - 1)), strconv.Itoa(int((indexA - 1) * 2))}, ".") + "/31"
	linkPrefixIpv4B := strings.Join([]string{"100.66", strconv.Itoa(int(indexB - 1)), strconv.Itoa(int((indexA-1)*2 + 1))}, ".") + "/31"
	var linkPrefixIpv6A string
	if int((indexA-1)*2) == 0 {
		linkPrefixIpv6A = strings.Join([]string{"1000:66", strconv.Itoa(int(indexB - 1))}, ":") + "::" + "/127"
	} else {
		linkPrefixIpv6A = strings.Join([]string{"1000:66", strconv.Itoa(int(indexB - 1))}, ":") + "::" + strconv.Itoa(int((indexA-1)*2)) + "/127"
	}
	linkPrefixIpv6B := strings.Join([]string{"1000:66", strconv.Itoa(int(indexB - 1))}, ":") + "::" + strconv.Itoa(int((indexA-1)*2+1)) + "/127"

	lacpFallBack := false
	for idx := 0; idx <= 1; idx++ {
		deviceName, itfceName := getDeviceItfce(idx, link)
		if strings.Contains(itfceName, "lag") {
			itfceName = strings.ReplaceAll(itfceName, "-", "")
			itfceName = strings.ReplaceAll(itfceName, "49", "31")
			itfceName = strings.ReplaceAll(itfceName, "50", "32")
			lacpFallBack, _ = getLagInfo(idx, link)
		}

		if strings.Contains(itfceName, "int-") {
			itfceName = strings.ReplaceAll(itfceName, "int", "ethernet")
			split := strings.Split(itfceName, "/")
			if len(split) > 2 {
				itfceName = "ethernet-" + split[len(split)-2] + "/" + split[len(split)-1]
			}
		}

		s.AddChild(deviceName, intentsrl3v1alpha1.InitSrl(r.client, s, deviceName))
		srld := s.GetChildData(deviceName)
		d, ok := srld.(*ygotsrl.Device)
		if !ok {
			return errors.New("expected ygot struct")
		}

		i := d.GetOrCreateInterface(itfceName)

		if strings.Contains(itfceName, "lag") {
			lagType := ygotsrl.SrlNokiaInterfacesLag_LagType_static
			if link.GetLacp() {
				lagType = ygotsrl.SrlNokiaInterfacesLag_LagType_lacp
			}

			if lacpFallBack {
				i.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
				i.Description = ygot.String("ndd-infra" + itfceName)
				i.Lag = &ygotsrl.SrlNokiaInterfaces_Interface_Lag{
					Lacp: &ygotsrl.SrlNokiaInterfaces_Interface_Lag_Lacp{
						Interval: ygotsrl.SrlNokiaLacp_LacpPeriodType_SLOW,
						LacpMode: ygotsrl.SrlNokiaLacp_LacpActivityType_ACTIVE,
					},
					LacpFallbackMode: ygotsrl.SrlNokiaInterfacesLag_LacpFallbackType_static,
					LagType:          ygotsrl.SrlNokiaInterfacesLag_LagType_lacp,
					MemberSpeed:      ygotsrl.SrlNokiaInterfacesLag_MemberSpeedType_100G,
				}
			} else {
				i.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
				i.Description = ygot.String("ndd-infra" + itfceName)
				i.Lag = &ygotsrl.SrlNokiaInterfaces_Interface_Lag{
					Lacp: &ygotsrl.SrlNokiaInterfaces_Interface_Lag_Lacp{
						Interval: ygotsrl.SrlNokiaLacp_LacpPeriodType_SLOW,
						LacpMode: ygotsrl.SrlNokiaLacp_LacpActivityType_ACTIVE,
					},
					LagType:     lagType,
					MemberSpeed: ygotsrl.SrlNokiaInterfacesLag_MemberSpeedType_100G,
				}
			}
		} else {
			i.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
			i.Description = ygot.String("ndd-infra" + itfceName)
		}

		var ipv4 *ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4
		var ipv6 *ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6

		for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
			switch af {
			case string(ipamv1alpha1.AddressFamilyIpv4):
				if idx == 0 {
					ipv4 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4{
						Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4_Address{
							linkPrefixIpv4A: {
								IpPrefix: ygot.String(linkPrefixIpv4A),
							},
						},
					}
				} else {
					ipv4 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4{
						Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv4_Address{
							linkPrefixIpv4A: {
								IpPrefix: ygot.String(linkPrefixIpv4B),
							},
						},
					}
				}
			case string(ipamv1alpha1.AddressFamilyIpv6):
				if idx == 0 {
					ipv6 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6{
						Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6_Address{
							linkPrefixIpv6A: {
								IpPrefix: ygot.String(linkPrefixIpv6A),
							},
						},
					}
				} else {
					ipv6 = &ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6{
						Address: map[string]*ygotsrl.SrlNokiaInterfaces_Interface_Subinterface_Ipv6_Address{
							linkPrefixIpv6A: {
								IpPrefix: ygot.String(linkPrefixIpv6B),
							},
						},
					}
				}
			}
		}

		siIndex := 0

		si := i.GetOrCreateSubinterface(uint32(siIndex))
		si.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
		si.Description = ygot.String("ndd-infra" + itfceName)
		si.Ipv4 = ipv4
		si.Ipv6 = ipv6

		ni := d.GetOrCreateNetworkInstance("default")
		ni.GetOrCreateInterface(itfceName + "." + strconv.Itoa(siIndex))

		r.log.Debug("networkinstance default", "added", itfceName+"."+strconv.Itoa(siIndex))

		bgp := ni.GetOrCreateProtocols().GetOrCreateBgp()
		if idx == 0 {
			bgpNeighbor := bgp.GetOrCreateNeighbor(strings.Split(linkPrefixIpv4B, "/")[0])
			bgpNeighbor.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
			bgpNeighbor.LocalAs = map[uint32]*ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Neighbor_LocalAs{
				*nodeInfo[0].as: {
					AsNumber: ygot.Uint32(*nodeInfo[0].as),
				},
			}
			bgpNeighbor.PeerGroup = ygot.String("underlay")
			bgpNeighbor.PeerAs = ygot.Uint32(*nodeInfo[1].as)
			bgpNeighbor.PeerAddress = ygot.String(strings.Split(linkPrefixIpv4B, "/")[0])
			bgpNeighbor.Transport = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Neighbor_Transport{
				LocalAddress: ygot.String(strings.Split(linkPrefixIpv4A, "/")[0]),
			}
		} else {
			bgpNeighbor := bgp.GetOrCreateNeighbor(strings.Split(linkPrefixIpv4A, "/")[0])
			bgpNeighbor.AdminState = ygotsrl.SrlNokiaCommon_AdminState_enable
			bgpNeighbor.LocalAs = map[uint32]*ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Neighbor_LocalAs{
				*nodeInfo[0].as: {
					AsNumber: ygot.Uint32(*nodeInfo[1].as),
				},
			}
			bgpNeighbor.PeerGroup = ygot.String("underlay")
			bgpNeighbor.PeerAs = ygot.Uint32(*nodeInfo[0].as)
			bgpNeighbor.PeerAddress = ygot.String(strings.Split(linkPrefixIpv4A, "/")[0])
			bgpNeighbor.Transport = &ygotsrl.SrlNokiaNetworkInstance_NetworkInstance_Protocols_Bgp_Neighbor_Transport{
				LocalAddress: ygot.String(strings.Split(linkPrefixIpv4B, "/")[0]),
			}
		}
	}

	return nil
}
*/

/*
func getLoopbackIpv4(cr *infrav1alpha1.Infrastructure, index uint32) (*string, error) {
	if cr.GetCidr() != nil && cr.GetLoopbackCidrIpv4() != "" {
		p, err := netaddr.ParseIPPrefix(cr.GetLoopbackCidrIpv4())
		if err != nil {
			return nil, err
		}
		ip, err := GetIndexedIP(p.IPNet(), int(index))
		if err != nil {
			return nil, err
		}
		prefixLength := 32
		ipPrefix := ip.String() + "/" + strconv.Itoa(prefixLength)
		return &ipPrefix, nil
	} else {
		return nil, errors.New("infra needs a valid loopback ipv4 cidr")
	}
}
*/
/*
func getLoopbackIpv6(cr *infrav1alpha1.Infrastructure, index uint32) (*string, error) {
	if cr.GetCidr() != nil && cr.GetLoopbackCidrIpv6() != "" {
		p, err := netaddr.ParseIPPrefix(cr.GetLoopbackCidrIpv6())
		if err != nil {
			return nil, err
		}
		ip, err := GetIndexedIP(p.IPNet(), int(index))
		if err != nil {
			return nil, err
		}
		prefixLength := 128
		ipPrefix := ip.String() + "/" + strconv.Itoa(prefixLength)
		return &ipPrefix, nil
	} else {
		return nil, errors.New("infra needs a valid loopback ipv6 cidr")
	}
}
*/

/*
func getAS(cr *infrav1alpha1.Infrastructure, index uint32) (*uint32, error) {
	if cr.GetAsPool() != nil && cr.GetAsPoolStart() != 0 && cr.GetAsPoolEnd() != 0 {
		as := cr.GetAsPoolStart() + index
		if as > cr.GetAsPoolEnd() {
			return nil, errors.New("infra as pool is not big enough")
		}
		return &as, nil
	}
	return nil, errors.New("infra as pool not assigned")
}
*/

/*
func getLagInfo(i int, link topov1alpha1.Tl) (bool, string) {
	var lacpFallback bool
	var lagName string
	switch i {
	case 0:
		lacpFallback = link.GetLacpFallbackA()
		lagName = link.GetLagAName()
	case 1:
		lacpFallback = link.GetLacpFallbackB()
		lagName = link.GetLagBName()
	}
	return lacpFallback, lagName
}
*/

/*
func getDeviceItfce(i int, link topov1alpha1.Tl) (string, string) {
	var deviceName, itfceName string
	switch i {
	case 0:
		deviceName = link.GetEndpointANodeName()
		itfceName = link.GetEndpointAInterfaceName()
	case 1:
		deviceName = link.GetEndpointBNodeName()
		itfceName = link.GetEndpointBInterfaceName()
	}
	return deviceName, itfceName
}
*/

/*
func getAddressFamilies(addressigSchem string) []string {
	var afs []string
	switch addressigSchem {
	case string(infrav1alpha1.AddressingSchemeDualStack):
		afs = []string{string(ipamv1alpha1.AddressFamilyIpv4), string(ipamv1alpha1.AddressFamilyIpv6)}
	case string(infrav1alpha1.AddressingSchemeIpv4Only):
		afs = []string{string(ipamv1alpha1.AddressFamilyIpv4)}
	case string(infrav1alpha1.AddressingSchemeIpv6Only):
		afs = []string{string(ipamv1alpha1.AddressFamilyIpv6)}
	}
	return afs
}
*/

/*
// GetIndexedIP returns a net.IP that is subnet.IP + index in the contiguous IP space.
func GetIndexedIP(subnet *net.IPNet, index int) (net.IP, error) {
	ip := addIPOffset(bigForIP(subnet.IP), index)
	if !subnet.Contains(ip) {
		return nil, fmt.Errorf("can't generate IP with index %d from subnet. subnet too small. subnet: %q", index, subnet)
	}
	return ip, nil
}
*/

/*
// addIPOffset adds the provided integer offset to a base big.Int representing a
// net.IP
func addIPOffset(base *big.Int, offset int) net.IP {
	return net.IP(big.NewInt(0).Add(base, big.NewInt(int64(offset))).Bytes())
}
*/

/*
// bigForIP creates a big.Int based on the provided net.IP
func bigForIP(ip net.IP) *big.Int {
	b := ip.To4()
	if b == nil {
		b = ip.To16()
	}
	return big.NewInt(0).SetBytes(b)
}
*/
