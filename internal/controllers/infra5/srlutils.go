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

package infra5

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/utils"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/odns"
	"github.com/yndd/nddo-runtime/pkg/resource"
	srlv1alpha1 "github.com/yndd/nddp-srl/apis/srl/v1alpha1"
	srlschemav1alpha1 "github.com/yndd/nddp-srl/pkg/srlschema/v1alpha1"
	ipamv1alpha1 "github.com/yndd/nddr-ipam-registry/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	"inet.af/netaddr"
	"k8s.io/apimachinery/pkg/types"
)

func (r *application) SrlPopulateNode(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}

	crName := getCrName(mg)
	s := r.srlHandler.InitSchema(crName)

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

		d := s.NewDevice(r.client, deviceName)

		fullIdx := getIndex(node.GetNodeIndex(), node.GetPosition())
		var err error

		as, err := getAS(cr, fullIdx)
		if err != nil {
			return err
		}

		var ipv4 *srlv1alpha1.InterfaceSubinterfaceIpv4
		var ipv6 *srlv1alpha1.InterfaceSubinterfaceIpv6
		var ipv4Prefix *string
		var ipv6Prefix *string
		for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
			switch af {
			case string(ipamv1alpha1.AddressFamilyIpv4):
				ipv4Prefix, err = getLoopbackIpv4(cr, fullIdx)
				if err != nil {
					return err
				}

				ipv4 = &srlv1alpha1.InterfaceSubinterfaceIpv4{
					Address: []*srlv1alpha1.InterfaceSubinterfaceIpv4Address{
						{
							Ipprefix: ipv4Prefix,
						},
					},
				}
			case string(ipamv1alpha1.AddressFamilyIpv6):
				ipv6Prefix, err = getLoopbackIpv6(cr, fullIdx)
				if err != nil {
					return err
				}

				ipv6 = &srlv1alpha1.InterfaceSubinterfaceIpv6{
					Address: []*srlv1alpha1.InterfaceSubinterfaceIpv6Address{
						{
							Ipprefix: ipv6Prefix,
						},
					},
				}

			}
		}
		i := r.createInterface(d, "system0")

		siIndex := 0
		si := i.NewInterfaceSubinterface(r.client, srlschemav1alpha1.WithInterfaceSubinterfaceKey(&srlschemav1alpha1.InterfaceSubinterfaceKey{
			Index: strconv.Itoa(siIndex),
		}))
		si.Update(&srlv1alpha1.InterfaceSubinterface{
			Index: utils.Uint32Ptr(uint32(siIndex)),
			Ipv4:  ipv4,
			Ipv6:  ipv6,
		})

		r.createInterface(d, "irb0")
		r.createTunnelInterface(d)

		psipv4 := d.NewRoutingpolicyPrefixset(r.client, srlschemav1alpha1.WithRoutingpolicyPrefixsetKey(&srlschemav1alpha1.RoutingpolicyPrefixsetKey{
			Name: "local-ipv4",
		}))

		psipv6 := d.NewRoutingpolicyPrefixset(r.client, srlschemav1alpha1.WithRoutingpolicyPrefixsetKey(&srlschemav1alpha1.RoutingpolicyPrefixsetKey{
			Name: "local-ipv6",
		}))

		psipv4.Update(&srlv1alpha1.RoutingpolicyPrefixset{
			Name: utils.StringPtr("local-ipv4"),
			Prefix: []*srlv1alpha1.RoutingpolicyPrefixsetPrefix{
				{
					Ipprefix:        utils.StringPtr(cr.GetLoopbackCidrIpv4()),
					Masklengthrange: utils.StringPtr("32..32"),
				},
			},
		})

		psipv6.Update(&srlv1alpha1.RoutingpolicyPrefixset{
			Name: utils.StringPtr("local-ipv6"),
			Prefix: []*srlv1alpha1.RoutingpolicyPrefixsetPrefix{
				{
					Ipprefix:        utils.StringPtr(cr.GetLoopbackCidrIpv6()),
					Masklengthrange: utils.StringPtr("128..128"),
				},
			},
		})

		rp := d.NewRoutingpolicyPolicy(r.client, srlschemav1alpha1.WithRoutingpolicyPolicyKey(&srlschemav1alpha1.RoutingpolicyPolicyKey{
			Name: "export-local",
		}))

		rp.Update(&srlv1alpha1.RoutingpolicyPolicy{
			Name: utils.StringPtr("export-local"),
			Statement: []*srlv1alpha1.RoutingpolicyPolicyStatement{
				{
					Sequenceid: utils.Uint32Ptr(10),
					Match: &srlv1alpha1.RoutingpolicyPolicyStatementMatch{
						Prefixset: utils.StringPtr("local-ipv4"),
					},
					Action: &srlv1alpha1.RoutingpolicyPolicyStatementAction{
						Accept: &srlv1alpha1.RoutingpolicyPolicyStatementActionAccept{},
					},
				},
				{
					Sequenceid: utils.Uint32Ptr(20),
					Match: &srlv1alpha1.RoutingpolicyPolicyStatementMatch{
						Prefixset: utils.StringPtr("local-ipv6"),
					},
					Action: &srlv1alpha1.RoutingpolicyPolicyStatementAction{
						Accept: &srlv1alpha1.RoutingpolicyPolicyStatementActionAccept{},
					},
				},
			},
		})

		niName := cr.GetNetworkInstanceName()
		ni := d.NewNetworkinstance(r.client, srlschemav1alpha1.WithNetworkinstanceKey(&srlschemav1alpha1.NetworkinstanceKey{
			Name: niName,
		}))

		if ni.Get() == nil {
			ni.Update(&srlv1alpha1.Networkinstance{
				Type:       utils.StringPtr("default"),
				Adminstate: srlv1alpha1.E_NetworkinstanceAdminstate_Enable,
				Name:       utils.StringPtr("default"),
			})
		}

		ni.AddNetworkinstanceInterface(&srlv1alpha1.NetworkinstanceInterface{
			Name: utils.StringPtr("system0.0"),
		})

		r.log.Debug("networkinstance default", "added", "system0.0")

		bgp := ni.NewNetworkinstanceProtocolsBgp(r.client, srlschemav1alpha1.WithNetworkinstanceProtocolsBgpKey(&srlschemav1alpha1.NetworkinstanceProtocolsBgpKey{}))

		if bgp.Get() == nil {
			bgp.Update(&srlv1alpha1.NetworkinstanceProtocolsBgp{
				Adminstate:       srlv1alpha1.E_NetworkinstanceProtocolsBgpAdminstate_Enable,
				Autonomoussystem: as,
				Routerid:         utils.StringPtr(strings.Split(*ipv4Prefix, "/")[0]),
				Ebgpdefaultpolicy: &srlv1alpha1.NetworkinstanceProtocolsBgpEbgpdefaultpolicy{
					Exportrejectall: utils.BoolPtr(false),
					Importrejectall: utils.BoolPtr(false),
				},
				Group: []*srlv1alpha1.NetworkinstanceProtocolsBgpGroup{
					{
						Groupname:  utils.StringPtr("overlay"),
						Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpGroupAdminstate_Enable,
						Evpn: &srlv1alpha1.NetworkinstanceProtocolsBgpGroupEvpn{
							Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpGroupEvpnAdminstate_Enable,
						},
					},
					{
						Groupname:    utils.StringPtr("underlay"),
						Adminstate:   srlv1alpha1.E_NetworkinstanceProtocolsBgpGroupAdminstate_Enable,
						Nexthopself:  utils.BoolPtr(true),
						Exportpolicy: utils.StringPtr("export-local"),
						Ipv4unicast: &srlv1alpha1.NetworkinstanceProtocolsBgpGroupIpv4unicast{
							Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpGroupIpv4unicastAdminstate_Enable,
						},
						Ipv6unicast: &srlv1alpha1.NetworkinstanceProtocolsBgpGroupIpv6unicast{
							Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpGroupIpv6unicastAdminstate_Enable,
						},
						Evpn: &srlv1alpha1.NetworkinstanceProtocolsBgpGroupEvpn{
							Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpGroupEvpnAdminstate_Enable,
						},
						/*
							Aspathoptions: &srlv1alpha1.NetworkinstanceProtocolsBgpGroupAspathoptions{
								Allowownas: utils.Uint8Ptr(0),
								Removeprivateas: &srlv1alpha1.NetworkinstanceProtocolsBgpGroupAspathoptionsRemoveprivateas{
									Leadingonly: utils.BoolPtr(true),
									Mode:        srlv1alpha1.E_NetworkinstanceProtocolsBgpGroupAspathoptionsRemoveprivateasMode_Delete,
								},
							},
						*/
					},
				},
				Ipv4unicast: &srlv1alpha1.NetworkinstanceProtocolsBgpIpv4unicast{
					Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpIpv4unicastAdminstate_Enable,
					Multipath: &srlv1alpha1.NetworkinstanceProtocolsBgpIpv4unicastMultipath{
						Allowmultipleas: utils.BoolPtr(true),
						Maxpathslevel1:  utils.Uint32Ptr(64),
						Maxpathslevel2:  utils.Uint32Ptr(64),
					},
				},
				Ipv6unicast: &srlv1alpha1.NetworkinstanceProtocolsBgpIpv6unicast{
					Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpIpv6unicastAdminstate_Enable,
					Multipath: &srlv1alpha1.NetworkinstanceProtocolsBgpIpv6unicastMultipath{
						Allowmultipleas: utils.BoolPtr(true),
						Maxpathslevel1:  utils.Uint32Ptr(64),
						Maxpathslevel2:  utils.Uint32Ptr(64),
					},
				},
				Evpn: &srlv1alpha1.NetworkinstanceProtocolsBgpEvpn{
					Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpEvpnAdminstate_Enable,
				},
			})
		}
		sysbgpvpn := d.NewSystemNetworkinstanceProtocolsBgpvpn(r.client,
			srlschemav1alpha1.WithSystemNetworkinstanceProtocolsBgpvpnKey(&srlschemav1alpha1.SystemNetworkinstanceProtocolsBgpvpnKey{}))

		// TODO can we make this better? we need to initialize this right now, otherwise the add fails
		sysbgpvpn.Update(&srlv1alpha1.SystemNetworkinstanceProtocolsBgpvpn{
			Bgpinstance: make([]*srlv1alpha1.SystemNetworkinstanceProtocolsBgpvpnBgpinstance, 0),
		})

		sysbgpvpn.AddSystemNetworkinstanceProtocolsBgpvpnBgpinstance(&srlv1alpha1.SystemNetworkinstanceProtocolsBgpvpnBgpinstance{
			Id: utils.Uint8Ptr(1),
		})

		sysbgpevpn := d.NewSystemNetworkinstanceProtocolsEvpn(r.client,
			srlschemav1alpha1.WithSystemNetworkinstanceProtocolsBgpvpnKey(&srlschemav1alpha1.SystemNetworkinstanceProtocolsBgpvpnKey{}))

		/*
			sysbgpevpn.Update(&srlv1alpha1.SystemNetworkinstanceProtocolsEvpn{
				Ethernetsegments: &srlv1alpha1.SystemNetworkinstanceProtocolsEvpnEthernetsegments{},
			})
		*/

		sysbgpevpnInst := sysbgpevpn.NewSystemNetworkinstanceProtocolsEvpnEsisBgpinstance(r.client,
			srlschemav1alpha1.WithSystemNetworkinstanceProtocolsEvpnEsisBgpinstanceKey(&srlschemav1alpha1.SystemNetworkinstanceProtocolsEvpnEsisBgpinstanceKey{
				Id: "1",
			}))

		sysbgpevpnInst.Update(&srlv1alpha1.SystemNetworkinstanceProtocolsEvpnEsisBgpinstance{
			Id: utils.StringPtr("1"),
		})
	}
	return nil
}

func (r *application) createTunnelInterface(d srlschemav1alpha1.Device) srlschemav1alpha1.Tunnelinterface {
	ti := d.NewTunnelinterface(r.client, srlschemav1alpha1.WithTunnelinterfaceKey(&srlschemav1alpha1.TunnelinterfaceKey{
		Name: "vxlan0",
	}))
	ti.Update(&srlv1alpha1.Tunnelinterface{
		Name: utils.StringPtr("vxlan0"),
	})
	return ti
}

func (r *application) createInterface(d srlschemav1alpha1.Device, itfceName string) srlschemav1alpha1.Interface {
	i := d.NewInterface(r.client, srlschemav1alpha1.WithInterfaceKey(&srlschemav1alpha1.InterfaceKey{
		Name: itfceName,
	}))
	i.Update(&srlv1alpha1.Interface{
		Adminstate: srlv1alpha1.E_InterfaceAdminstate_Enable,
		Name:       utils.StringPtr(itfceName),
	})
	return i
}

func (r *application) SrlPopulateLagMember(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	crName := getCrName(mg)
	s := r.srlHandler.InitSchema(crName)

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

		d := s.NewDevice(r.client, deviceName)

		i := d.NewInterface(r.client, srlschemav1alpha1.WithInterfaceKey(&srlschemav1alpha1.InterfaceKey{
			Name: itfceName,
		}))

		i.Update(&srlv1alpha1.Interface{
			Adminstate: srlv1alpha1.E_InterfaceAdminstate_Enable,
			Name:       &itfceName,
			Ethernet: &srlv1alpha1.InterfaceEthernet{
				Aggregateid: utils.StringPtr(lagName),
				Portspeed:   srlv1alpha1.E_InterfaceEthernetPortspeed_100g,
			},
		})
	}
	return nil
}

type nodeInfo struct {
	position *string
	index    *uint32
	as       *uint32
	itfceIdx *uint32
}

func getNodeInfo(cr *infrav1alpha1.Infrastructure, node topov1alpha1.Tn, itfceName string) (*nodeInfo, error) {
	// TODO move to ASpoll per tier
	fullIdx := getIndex(node.GetNodeIndex(), node.GetPosition())

	as, err := getAS(cr, fullIdx)
	if err != nil {
		return nil, err
	}

	// interfaceindex
	// TODO changed when using IXR-6/10
	split := strings.Split(itfceName, "/")
	ifidx, err := strconv.Atoi(split[len(split)-1])
	if err != nil {
		return nil, err
	}

	return &nodeInfo{
		position: utils.StringPtr(node.GetPosition()),
		index:    utils.Uint32Ptr(node.GetNodeIndex()),
		as:       as,
		itfceIdx: utils.Uint32Ptr(uint32(ifidx)),
	}, nil
}

func (r *application) SrlPopulateIpLink(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}
	crName := getCrName(mg)
	s := r.srlHandler.InitSchema(crName)

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
		if *nodeInfo[idx].position == "spine" {
			spineIdx = idx
		}
		if *nodeInfo[idx].position == "leaf" {
			leafIdx = idx
		}

	}
	leaf2leaf := false
	if *nodeInfo[0].position == "leaf" && *nodeInfo[1].position == "leaf" {
		leaf2leaf = true
	}

	var indexA, indexB uint32
	if leaf2leaf {
		indexA = *nodeInfo[0].itfceIdx
		indexB = *nodeInfo[1].itfceIdx
	} else {
		indexB = *nodeInfo[spineIdx].itfceIdx
		indexA = *nodeInfo[leafIdx].itfceIdx
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

		d := s.NewDevice(r.client, deviceName)

		i := d.NewInterface(r.client, srlschemav1alpha1.WithInterfaceKey(&srlschemav1alpha1.InterfaceKey{
			Name: itfceName,
		}))

		if strings.Contains(itfceName, "lag") {
			lagType := srlv1alpha1.E_InterfaceLagLagtype_Static
			if link.GetLacp() {
				lagType = srlv1alpha1.E_InterfaceLagLagtype_Lacp
			}

			if lacpFallBack {
				i.Update(&srlv1alpha1.Interface{
					Adminstate: srlv1alpha1.E_InterfaceAdminstate_Enable,
					Name:       &itfceName,
					Lag: &srlv1alpha1.InterfaceLag{
						Lacp: &srlv1alpha1.InterfaceLagLacp{
							Interval: srlv1alpha1.E_InterfaceLagLacpInterval_Slow,
							Lacpmode: srlv1alpha1.E_InterfaceLagLacpLacpmode_Active,
						},
						Lacpfallbackmode: srlv1alpha1.E_InterfaceLagLacpfallbackmode_Static,
						Lagtype:          srlv1alpha1.E_InterfaceLagLagtype_Lacp,
						Memberspeed:      srlv1alpha1.E_InterfaceLagMemberspeed_100g,
					},
				})
			} else {
				i.Update(&srlv1alpha1.Interface{
					Adminstate: srlv1alpha1.E_InterfaceAdminstate_Enable,
					Name:       &itfceName,
					Lag: &srlv1alpha1.InterfaceLag{
						Lacp: &srlv1alpha1.InterfaceLagLacp{
							Interval: srlv1alpha1.E_InterfaceLagLacpInterval_Slow,
							Lacpmode: srlv1alpha1.E_InterfaceLagLacpLacpmode_Active,
						},
						Lagtype:     lagType,
						Memberspeed: srlv1alpha1.E_InterfaceLagMemberspeed_100g,
					},
				})
			}
		} else {
			i.Update(&srlv1alpha1.Interface{
				Adminstate: srlv1alpha1.E_InterfaceAdminstate_Enable,
				Name:       &itfceName,
			})
		}

		var ipv4 *srlv1alpha1.InterfaceSubinterfaceIpv4
		var ipv6 *srlv1alpha1.InterfaceSubinterfaceIpv6
		for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
			switch af {
			case string(ipamv1alpha1.AddressFamilyIpv4):
				if idx == 0 {
					ipv4 = &srlv1alpha1.InterfaceSubinterfaceIpv4{
						Address: []*srlv1alpha1.InterfaceSubinterfaceIpv4Address{
							{
								Ipprefix: utils.StringPtr(linkPrefixIpv4A),
							},
						},
					}
				} else {
					ipv4 = &srlv1alpha1.InterfaceSubinterfaceIpv4{
						Address: []*srlv1alpha1.InterfaceSubinterfaceIpv4Address{
							{
								Ipprefix: utils.StringPtr(linkPrefixIpv4B),
							},
						},
					}
				}

			case string(ipamv1alpha1.AddressFamilyIpv6):
				if idx == 0 {
					ipv6 = &srlv1alpha1.InterfaceSubinterfaceIpv6{
						Address: []*srlv1alpha1.InterfaceSubinterfaceIpv6Address{
							{
								Ipprefix: utils.StringPtr(linkPrefixIpv6A),
							},
						},
					}
				} else {
					ipv6 = &srlv1alpha1.InterfaceSubinterfaceIpv6{
						Address: []*srlv1alpha1.InterfaceSubinterfaceIpv6Address{
							{
								Ipprefix: utils.StringPtr(linkPrefixIpv6B),
							},
						},
					}
				}
			}
		}

		siIndex := 0
		si := i.NewInterfaceSubinterface(r.client, srlschemav1alpha1.WithInterfaceSubinterfaceKey(&srlschemav1alpha1.InterfaceSubinterfaceKey{
			Index: strconv.Itoa(siIndex),
		}))
		si.Update(&srlv1alpha1.InterfaceSubinterface{
			Adminstate: srlv1alpha1.E_InterfaceSubinterfaceAdminstate_Enable,
			Index:      utils.Uint32Ptr(uint32(siIndex)),
			Ipv4:       ipv4,
			Ipv6:       ipv6,
		})

		//niIndex := 333
		//niName := cr.GetNetworkInstanceName()
		ni := d.NewNetworkinstance(r.client, srlschemav1alpha1.WithNetworkinstanceKey(&srlschemav1alpha1.NetworkinstanceKey{
			Name: "default",
		}))

		ni.AddNetworkinstanceInterface(&srlv1alpha1.NetworkinstanceInterface{
			Name: utils.StringPtr(itfceName + "." + strconv.Itoa(siIndex)),
		})

		r.log.Debug("networkinstance default", "added", itfceName+"."+strconv.Itoa(siIndex))

		bgp := ni.NewNetworkinstanceProtocolsBgp(r.client, srlschemav1alpha1.WithNetworkinstanceProtocolsBgpKey(&srlschemav1alpha1.NetworkinstanceProtocolsBgpKey{}))

		if idx == 0 {
			bgp.AddNetworkinstanceProtocolsBgpNeighbor(&srlv1alpha1.NetworkinstanceProtocolsBgpNeighbor{
				Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpNeighborAdminstate_Enable,
				Localas: []*srlv1alpha1.NetworkinstanceProtocolsBgpNeighborLocalas{
					{
						Asnumber: nodeInfo[0].as,
					},
				},
				Peeras:    nodeInfo[1].as,
				Peergroup: utils.StringPtr("underlay"),
				//Peeraddress: &linkPrefixIpv4B,
				Peeraddress: utils.StringPtr(strings.Split(linkPrefixIpv4B, "/")[0]),
				Transport: &srlv1alpha1.NetworkinstanceProtocolsBgpNeighborTransport{
					Localaddress: utils.StringPtr(strings.Split(linkPrefixIpv4A, "/")[0]),
				},
			})
			bgp.AddNetworkinstanceProtocolsBgpNeighbor(&srlv1alpha1.NetworkinstanceProtocolsBgpNeighbor{
				Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpNeighborAdminstate_Enable,
				Localas: []*srlv1alpha1.NetworkinstanceProtocolsBgpNeighborLocalas{
					{
						Asnumber: nodeInfo[0].as,
					},
				},
				Peeras:    nodeInfo[1].as,
				Peergroup: utils.StringPtr("underlay"),
				//Peeraddress: &linkPrefixIpv6B,
				Peeraddress: utils.StringPtr(strings.Split(linkPrefixIpv6B, "/")[0]),
				Transport: &srlv1alpha1.NetworkinstanceProtocolsBgpNeighborTransport{
					Localaddress: utils.StringPtr(strings.Split(linkPrefixIpv6A, "/")[0]),
				},
			})
		} else {
			bgp.AddNetworkinstanceProtocolsBgpNeighbor(&srlv1alpha1.NetworkinstanceProtocolsBgpNeighbor{
				Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpNeighborAdminstate_Enable,
				Localas: []*srlv1alpha1.NetworkinstanceProtocolsBgpNeighborLocalas{
					{
						Asnumber: nodeInfo[1].as,
					},
				},
				Peeras:    nodeInfo[0].as,
				Peergroup: utils.StringPtr("underlay"),
				//Peeraddress: &linkPrefixIpv4A,
				Peeraddress: utils.StringPtr(strings.Split(linkPrefixIpv4A, "/")[0]),
				Transport: &srlv1alpha1.NetworkinstanceProtocolsBgpNeighborTransport{
					Localaddress: utils.StringPtr(strings.Split(linkPrefixIpv4B, "/")[0]),
				},
			})
			bgp.AddNetworkinstanceProtocolsBgpNeighbor(&srlv1alpha1.NetworkinstanceProtocolsBgpNeighbor{
				Adminstate: srlv1alpha1.E_NetworkinstanceProtocolsBgpNeighborAdminstate_Enable,
				Localas: []*srlv1alpha1.NetworkinstanceProtocolsBgpNeighborLocalas{
					{
						Asnumber: nodeInfo[1].as,
					},
				},
				Peeras:    nodeInfo[0].as,
				Peergroup: utils.StringPtr("underlay"),
				//Peeraddress: &linkPrefixIpv6A,
				Peeraddress: utils.StringPtr(strings.Split(linkPrefixIpv6A, "/")[0]),
				Transport: &srlv1alpha1.NetworkinstanceProtocolsBgpNeighborTransport{
					Localaddress: utils.StringPtr(strings.Split(linkPrefixIpv6B, "/")[0]),
				},
			})
		}
	}

	return nil
}

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

func getIndex(index uint32, position string) uint32 {
	offset := uint32(0)
	switch position {
	case "leaf":
		offset = 0
		return offset + index
	case "spine": //issue with 
		offset = 64
		return offset
	case "superspine":
		offset = 128
		return offset
	}
	return 0
}

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

// GetIndexedIP returns a net.IP that is subnet.IP + index in the contiguous IP space.
func GetIndexedIP(subnet *net.IPNet, index int) (net.IP, error) {
	ip := addIPOffset(bigForIP(subnet.IP), index)
	if !subnet.Contains(ip) {
		return nil, fmt.Errorf("can't generate IP with index %d from subnet. subnet too small. subnet: %q", index, subnet)
	}
	return ip, nil
}

// addIPOffset adds the provided integer offset to a base big.Int representing a
// net.IP
func addIPOffset(base *big.Int, offset int) net.IP {
	return net.IP(big.NewInt(0).Add(base, big.NewInt(int64(offset))).Bytes())
}

// bigForIP creates a big.Int based on the provided net.IP
func bigForIP(ip net.IP) *big.Int {
	b := ip.To4()
	if b == nil {
		b = ip.To16()
	}
	return big.NewInt(0).SetBytes(b)
}
