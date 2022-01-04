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

	"github.com/yndd/nddo-grpc/resource/resourcepb"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-infrastructure/internal/infra"
	ipamv1alpha1 "github.com/yndd/nddr-ipam/apis/ipam/v1alpha1"
	"github.com/yndd/nddr-org-registry/pkg/registry"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	"inet.af/netaddr"
)

type interfaceParameters struct {
	nodeName     string
	kind         infra.InterfaceKind
	itfceName    string
	lagName      string
	lag          bool
	lagMember    bool
	lacp         bool
	lacpFallback bool

	// ni parameters
	niName  string
	niKind  infra.NiKind
	niIndex string
	//mh           bool
	//mhName       string
	tags map[string]string
	// references
	topologyName string
	asPoolName   string
	ipamName     string
	//client
	ipamClient   resourcepb.ResourceClient
	aspoolClient resourcepb.ResourceClient
}

func getLinkParameters(i int, niName string, link topov1alpha1.Tl, register map[string]string, ipamClient, aspoolClient resourcepb.ResourceClient) *interfaceParameters {
	switch i {
	case 0:
		ip := &interfaceParameters{
			nodeName:     link.GetEndpointANodeName(),
			kind:         infra.InterfaceKindInterface,
			itfceName:    link.GetEndpointAInterfaceName(),
			lagName:      link.GetLagAName(),
			lag:          link.GetLag(),
			lagMember:    link.GetLagMember(),
			lacp:         link.GetLacp(),
			lacpFallback: link.GetLacpFallbackA(),

			niName:  niName,
			niKind:  infra.NiKindRouted,
			niIndex: "0",
			//mh:           link.GetEndPointAMultiHoming(),
			//mhName:       link.GetEndPointAMultiHomingName(),
			tags:         link.GetEndpointATag(),
			topologyName: link.GetTopologyName(),
			asPoolName:   register[registry.RegisterKindAs.String()],
			ipamName:     register[registry.RegisterKindIpam.String()],
			ipamClient:   ipamClient,
			aspoolClient: aspoolClient,
		}
		return ip
	case 1:
		ip := &interfaceParameters{
			nodeName:     link.GetEndpointBNodeName(),
			kind:         infra.InterfaceKindInterface,
			itfceName:    link.GetEndpointBInterfaceName(),
			lagName:      link.GetLagBName(),
			lag:          link.GetLag(),
			lagMember:    link.GetLagMember(),
			lacp:         link.GetLacp(),
			lacpFallback: link.GetLacpFallbackB(),

			niName:  niName,
			niKind:  infra.NiKindRouted,
			niIndex: "0",
			//mh:           link.GetEndPointBMultiHoming(),
			//mhName:       link.GetEndPointBMultiHomingName(),
			tags:         link.GetEndpointATag(),
			topologyName: link.GetTopologyName(),
			asPoolName:   register[registry.RegisterKindAs.String()],
			ipamName:     register[registry.RegisterKindIpam.String()],
			ipamClient:   ipamClient,
			aspoolClient: aspoolClient,
		}
		return ip
	}
	return &interfaceParameters{}

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

func parseIpPerEndPoint(prefix string) ([]string, error) {
	ips := make([]string, 0, 2)
	p, err := netaddr.ParseIPPrefix(prefix)
	if err != nil {
		return nil, err
	}

	//log.Debug("Netaddr IP", "IP1", p.IP(), "IP2", p.IP().Next(), "Mask", p.Bits())
	switch {
	case p.Bits() == 31:
		ips = append(ips, strings.Join([]string{p.IP().String(), "32"}, "/"))
		ips = append(ips, strings.Join([]string{p.IP().Next().String(), "32"}, "/"))
		return ips, nil
	case p.Bits() == 127:
		ips = append(ips, strings.Join([]string{p.IP().String(), "128"}, "/"))
		ips = append(ips, strings.Join([]string{p.IP().Next().String(), "128"}, "/"))
		return ips, nil
	default:

	}
	return nil, err
}

func parseEndpointPrefix(linkPrefix, epPrefix string) (string, error) {
	lp, err := netaddr.ParseIPPrefix(linkPrefix)
	if err != nil {
		return "", err
	}
	ep, err := netaddr.ParseIPPrefix(epPrefix)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{ep.IP().String(), strconv.Itoa(int(lp.Bits()))}, "/"), nil
}
