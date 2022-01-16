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

package infra2

import (
	"context"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/utils"
	networkv1alpha1 "github.com/yndd/ndda-network/apis/network/v1alpha1"
	networkschemav1alpha1 "github.com/yndd/ndda-network/pkg/networkschema/v1alpha1"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/odns"
	"github.com/yndd/nddo-runtime/pkg/resource"
	ipamv1alpha1 "github.com/yndd/nddr-ipam-registry/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

func (r *application) PopulateNode(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}

	crName := getCrName(mg)
	s := r.networkHandler.InitSchema(crName)

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

		index := node.GetNodeIndex()

		// Allocate AS per node if the underlay protocol is ebgp
		/*
			for _, protocol := range cr.GetUnderlayProtocol() {
				if protocol == string(infrav1alpha1.ProtocolEBGP) {
					// TODO Allocate AS
					as := 65000 + index
				}
			}
		*/

		ipv4 := make([]*networkv1alpha1.InterfaceSubinterfaceIpv4, 0)
		ipv6 := make([]*networkv1alpha1.InterfaceSubinterfaceIpv6, 0)
		for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
			switch af {
			case string(ipamv1alpha1.AddressFamilyIpv4):
				prefixLength := 32
				ipAddress := "1.1.1." + strconv.Itoa(int(index))
				ipPrefix := ipAddress + "/" + strconv.Itoa(prefixLength)
				ipCidr := ipAddress + "/" + strconv.Itoa(prefixLength)

				ipv4 = append(ipv4, &networkv1alpha1.InterfaceSubinterfaceIpv4{
					IpPrefix: utils.StringPtr(ipPrefix),
					Config: &networkv1alpha1.InterfaceSubinterfaceIpv4Config{
						IpAddress:    utils.StringPtr(ipAddress),
						IpPrefix:     utils.StringPtr(ipPrefix),
						IpCidr:       utils.StringPtr(ipCidr),
						PrefixLength: utils.Uint32Ptr(uint32(prefixLength)),
					},
				})
			case string(ipamv1alpha1.AddressFamilyIpv6):
				prefixLength := 128
				ipAddress := "1000::" + strconv.Itoa(int(index))
				ipPrefix := ipAddress + "/" + strconv.Itoa(prefixLength)
				ipCidr := ipAddress + "/" + strconv.Itoa(prefixLength)

				ipv6 = append(ipv6, &networkv1alpha1.InterfaceSubinterfaceIpv6{
					IpPrefix: utils.StringPtr(ipPrefix),
					Config: &networkv1alpha1.InterfaceSubinterfaceIpv6Config{
						IpAddress:    utils.StringPtr(ipAddress),
						IpPrefix:     utils.StringPtr(ipPrefix),
						IpCidr:       utils.StringPtr(ipCidr),
						PrefixLength: utils.Uint32Ptr(uint32(prefixLength)),
					},
				})
			}
		}
		i := r.createInterface(d, "system", networkv1alpha1.E_InterfaceKind_LOOPBACK)

		siIndex := 0
		si := i.NewInterfaceSubinterface(r.client, networkschemav1alpha1.WithInterfaceSubinterfaceKey(&networkschemav1alpha1.InterfaceSubinterfaceKey{
			Index: strconv.Itoa(siIndex),
		}))
		si.Update(&networkv1alpha1.InterfaceSubinterface{
			Index: utils.StringPtr(strconv.Itoa(siIndex)),
			Config: &networkv1alpha1.InterfaceSubinterfaceConfig{
				Index:       utils.Uint32Ptr(uint32(siIndex)),
				InnerVlanId: utils.Uint16Ptr(uint16(siIndex)),
				OuterVlanId: utils.Uint16Ptr(uint16(siIndex)),
				Kind:        networkv1alpha1.E_InterfaceSubinterfaceKind_ROUTED,
			},
			Ipv4: ipv4,
			Ipv6: ipv6,
		})

		r.createInterface(d, "irb", networkv1alpha1.E_InterfaceKind_IRB)
		r.createInterface(d, "vxlan", networkv1alpha1.E_InterfaceKind_VXLAN)
	}
	return nil
}

func (r *application) createInterface(d networkschemav1alpha1.Device, itfceName string, kind networkv1alpha1.E_InterfaceKind) networkschemav1alpha1.Interface {
	i := d.NewInterface(r.client, networkschemav1alpha1.WithInterfaceKey(&networkschemav1alpha1.InterfaceKey{
		Name: itfceName,
	}))
	i.Update(&networkv1alpha1.Interface{
		Name: utils.StringPtr(itfceName),
		Config: &networkv1alpha1.InterfaceConfig{
			Kind:         kind,
			Lacp:         utils.BoolPtr(false),
			LacpFallback: utils.BoolPtr(false),
			LagMember:    utils.BoolPtr(false),
			Lag:          utils.BoolPtr(false),
			LagName:      utils.StringPtr(""),
		},
	})
	return i
}

func (r *application) PopulateLagMember(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	crName := getCrName(mg)
	s := r.networkHandler.InitSchema(crName)

	for idx := 0; idx <= 1; idx++ {

		deviceName, itfceName := getDeviceItfce(idx, link)
		lacpFallBack, lagName := getLagInfo(idx, link)

		d := s.NewDevice(r.client, deviceName)

		i := d.NewInterface(r.client, networkschemav1alpha1.WithInterfaceKey(&networkschemav1alpha1.InterfaceKey{
			Name: itfceName,
		}))

		i.Update(&networkv1alpha1.Interface{
			Name: &itfceName,
			Config: &networkv1alpha1.InterfaceConfig{
				Kind:         networkv1alpha1.E_InterfaceKind_INTERFACE,
				Lacp:         utils.BoolPtr(link.GetLacp()),
				LacpFallback: utils.BoolPtr(lacpFallBack),
				LagMember:    utils.BoolPtr(link.GetLagMember()),
				Lag:          utils.BoolPtr(link.GetLag()),
				LagName:      utils.StringPtr(lagName),
			},
		})
	}
	return nil
}

func (r *application) PopulateIpLink(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}
	crName := getCrName(mg)
	s := r.networkHandler.InitSchema(crName)

	for idx := 0; idx <= 1; idx++ {
		deviceName, itfceName := getDeviceItfce(idx, link)

		d := s.NewDevice(r.client, deviceName)

		i := d.NewInterface(r.client, networkschemav1alpha1.WithInterfaceKey(&networkschemav1alpha1.InterfaceKey{
			Name: itfceName,
		}))

		i.Update(&networkv1alpha1.Interface{
			Name: &itfceName,
			Config: &networkv1alpha1.InterfaceConfig{
				Kind:         networkv1alpha1.E_InterfaceKind_INTERFACE,
				Lacp:         utils.BoolPtr(false),
				LacpFallback: utils.BoolPtr(false),
				LagMember:    utils.BoolPtr(false),
				Lag:          utils.BoolPtr(link.GetLag()),
				//LagName:      utils.StringPtr(lagName),
			},
		})

		ipv4 := make([]*networkv1alpha1.InterfaceSubinterfaceIpv4, 0)
		ipv6 := make([]*networkv1alpha1.InterfaceSubinterfaceIpv6, 0)
		for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
			switch af {
			case string(ipamv1alpha1.AddressFamilyIpv4):
				prefixLength := 31
				ipAddress := "10.0.0." + strconv.Itoa(int(idx))
				ipPrefix := ipAddress + "/" + strconv.Itoa(prefixLength)
				ipCidr := ipAddress + "/" + strconv.Itoa(prefixLength)

				ipv4 = append(ipv4, &networkv1alpha1.InterfaceSubinterfaceIpv4{
					IpPrefix: utils.StringPtr(ipPrefix),
					Config: &networkv1alpha1.InterfaceSubinterfaceIpv4Config{
						IpAddress:    utils.StringPtr(ipAddress),
						IpPrefix:     utils.StringPtr(ipPrefix),
						IpCidr:       utils.StringPtr(ipCidr),
						PrefixLength: utils.Uint32Ptr(uint32(prefixLength)),
					},
				})
			case string(ipamv1alpha1.AddressFamilyIpv6):
				prefixLength := 127
				ipAddress := "2000::" + strconv.Itoa(int(idx))
				ipPrefix := ipAddress + "/" + strconv.Itoa(prefixLength)
				ipCidr := ipAddress + "/" + strconv.Itoa(prefixLength)

				ipv6 = append(ipv6, &networkv1alpha1.InterfaceSubinterfaceIpv6{
					IpPrefix: utils.StringPtr(ipPrefix),
					Config: &networkv1alpha1.InterfaceSubinterfaceIpv6Config{
						IpAddress:    utils.StringPtr(ipAddress),
						IpPrefix:     utils.StringPtr(ipPrefix),
						IpCidr:       utils.StringPtr(ipCidr),
						PrefixLength: utils.Uint32Ptr(uint32(prefixLength)),
					},
				})
			}
		}

		siIndex := 0
		si := i.NewInterfaceSubinterface(r.client, networkschemav1alpha1.WithInterfaceSubinterfaceKey(&networkschemav1alpha1.InterfaceSubinterfaceKey{
			Index: strconv.Itoa(siIndex),
		}))
		si.Update(&networkv1alpha1.InterfaceSubinterface{
			Index: utils.StringPtr(strconv.Itoa(siIndex)),
			Config: &networkv1alpha1.InterfaceSubinterfaceConfig{
				Index:       utils.Uint32Ptr(uint32(siIndex)),
				InnerVlanId: utils.Uint16Ptr(uint16(siIndex)),
				OuterVlanId: utils.Uint16Ptr(uint16(siIndex)),
				Kind:        networkv1alpha1.E_InterfaceSubinterfaceKind_ROUTED,
			},
			Ipv4: ipv4,
			Ipv6: ipv6,
		})

		niIndex := 333
		niName := cr.GetNetworkInstanceName()
		ni := d.NewNetworkInstance(r.client, networkschemav1alpha1.WithNetworkInstanceKey(&networkschemav1alpha1.NetworkInstanceKey{
			Name: niName,
		}))

		ni.Update(&networkv1alpha1.NetworkInstance{
			Name: utils.StringPtr(niName),
			Config: &networkv1alpha1.NetworkInstanceConfig{
				Name:  utils.StringPtr(niName),
				Index: utils.Uint32Ptr(uint32(niIndex)),
				Kind:  networkv1alpha1.E_NetworkInstanceKind_ROUTED,
			},
		})

		ni.AddNetworkInstanceInterface(&networkv1alpha1.NetworkInstanceConfigInterface{
			Name: utils.StringPtr(itfceName + "." + strconv.Itoa(siIndex)),
		})
	}

	return nil
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
