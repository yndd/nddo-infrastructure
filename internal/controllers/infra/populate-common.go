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
	"context"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/odns"
	"github.com/yndd/nddo-runtime/pkg/resource"
	ipamv1alpha1 "github.com/yndd/nddr-ipam-registry/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	"inet.af/netaddr"
	"k8s.io/apimachinery/pkg/types"
)

type nodeLinkInfo struct {
	name             string // devicename
	kind             string // srl, sros, etc
	platform         string // ixrd1, ixrd2, ixrd3, etc
	position         string // spine or leaf
	as               uint32 // as allocated
	nodeIdx          uint32 // index of the node in the system
	itfceIdx         uint32 // index of the interface -> ethernet-1/49 would be 49
	itfceName        string // name of the interface in abstract format
	lagName          string // name of the lag in abstract format
	linkPrefixIpv4   string // ipv4 prefix for the link
	linkPrefixIpv6   string // ipv6 prefix for the link
	systemPrefixIpv4 string // ipv4 prefix for the system/loopback IP
	systemPrefixIpv6 string // ipv6 prefix for the system/loopback IP
	lacp             bool
	lacpFallBack     bool
	lagMember        bool
}

func (r *application) gatherNodeLinkInfo(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) ([]*nodeLinkInfo, error) {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return nil, errors.New(errUnexpectedResource)
	}
	nodeLinkInfo := make([]*nodeLinkInfo, 2)
	spineIdx := 0
	leafIdx := 0
	// A link has 2 devices on each end so we walk to both ends and determine the nodeInfo
	//
	for idx := 0; idx <= 1; idx++ {
		deviceName, itfceName := getDeviceItfce(idx, link)
		_, lagName := getLagInfo(idx, link)
		node := r.newTopoNode()
		if err := r.client.Get(ctx, types.NamespacedName{
			Namespace: mg.GetNamespace(),
			Name:      strings.Join([]string{odns.GetParentResourceName(link.GetName()), deviceName}, "."),
		}, node); err != nil {
			// There's no need to requeue if we no longer exist. Otherwise we'll be
			// requeued implicitly because we return an error.
			//log.Debug("Cannot get managed resource", "error", err)
			return nil, err
		}

		var err error
		nodeLinkInfo[idx], err = getNodeInfo(cr, node, itfceName, lagName)
		if err != nil {
			return nil, err
		}
		n := nodeLinkInfo[idx]
		n.lacp = link.GetLacp()
		n.lagMember = link.GetLagMember()

		// TODOD move to pod idx per spine
		if n.position == "spine" {
			spineIdx = idx
		}
		if n.position == "leaf" {
			leafIdx = idx
		}
	}
	// the underlay allocation for ipv4 is xx.yy.spineItfceIdx.leafItfceIdx with /31
	// the udnerlay allocation for ipv6 is xx.yy.spineItfceIdx.leafItfceIdx::0 with /127
	// for leaf 2 leaf we just use the regular order and dont care, but we want a determinsitic allocation
	leaf2leaf := false
	if nodeLinkInfo[0].position == "leaf" && nodeLinkInfo[1].position == "leaf" {
		leaf2leaf = true
	}

	var indexA, indexB uint32
	if leaf2leaf {
		indexA = nodeLinkInfo[0].itfceIdx
		indexB = nodeLinkInfo[1].itfceIdx
	} else {
		indexB = nodeLinkInfo[spineIdx].itfceIdx
		indexA = nodeLinkInfo[leafIdx].itfceIdx
	}

	for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
		switch af {
		case string(ipamv1alpha1.AddressFamilyIpv4):
			// TODO 169.254.0.0/16
			nodeLinkInfo[0].linkPrefixIpv4 = strings.Join([]string{"169.254", strconv.Itoa(int(indexB - 1)), strconv.Itoa(int((indexA - 1) * 2))}, ".") + "/31"
			nodeLinkInfo[1].linkPrefixIpv4 = strings.Join([]string{"169.254", strconv.Itoa(int(indexB - 1)), strconv.Itoa(int((indexA-1)*2 + 1))}, ".") + "/31"
		case string(ipamv1alpha1.AddressFamilyIpv6):
			// TODO LLA
			if int((indexA-1)*2) == 0 {
				nodeLinkInfo[0].linkPrefixIpv6 = strings.Join([]string{"1169:254", strconv.Itoa(int(indexB - 1))}, ":") + "::" + "/127"
			} else {
				nodeLinkInfo[0].linkPrefixIpv6 = strings.Join([]string{"1169:254", strconv.Itoa(int(indexB - 1))}, ":") + "::" + strconv.Itoa(int((indexA-1)*2)) + "/127"
			}
			nodeLinkInfo[1].linkPrefixIpv6 = strings.Join([]string{"1169:254", strconv.Itoa(int(indexB - 1))}, ":") + "::" + strconv.Itoa(int((indexA-1)*2+1)) + "/127"
		}
	}
	return nodeLinkInfo, nil
}

func getNodeInfo(cr *infrav1alpha1.Infrastructure, node topov1alpha1.Tn, itfceName, lagName string) (*nodeLinkInfo, error) {
	// TODO move to ASpoll per tier
	fullIdx := getIndex(node.GetNodeIndex(), node.GetPosition())

	as, err := getAS(cr, fullIdx)
	if err != nil {
		return nil, err
	}

	var ipv4Prefix string
	var ipv6Prefix string
	for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
		switch af {
		case string(ipamv1alpha1.AddressFamilyIpv4):
			ipv4Prefix, err = getLoopbackIpv4(cr, fullIdx)
			if err != nil {
				return nil, err
			}
		case string(ipamv1alpha1.AddressFamilyIpv6):
			ipv6Prefix, err = getLoopbackIpv6(cr, fullIdx)
			if err != nil {
				return nil, err
			}
		}
	}

	// interfaceindex
	// TODO changed when using IXR-6/10
	split := strings.Split(itfceName, "/")
	ifidx, err := strconv.Atoi(split[len(split)-1])
	if err != nil {
		return nil, err
	}

	return &nodeLinkInfo{
		name:             node.GetNodeName(),
		kind:             node.GetKindName(),
		platform:         node.GetPlatform(),
		position:         node.GetPosition(),
		nodeIdx:          node.GetNodeIndex(),
		as:               as,
		itfceIdx:         uint32(ifidx),
		itfceName:        itfceName,
		lagName:          lagName,
		systemPrefixIpv4: ipv4Prefix,
		systemPrefixIpv6: ipv6Prefix,
	}, nil
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

func getLoopbackIpv4(cr *infrav1alpha1.Infrastructure, index uint32) (string, error) {
	if cr.GetCidr() != nil && cr.GetLoopbackCidrIpv4() != "" {
		p, err := netaddr.ParseIPPrefix(cr.GetLoopbackCidrIpv4())
		if err != nil {
			return "", err
		}
		ip, err := GetIndexedIP(p.IPNet(), int(index))
		if err != nil {
			return "", err
		}
		prefixLength := 32
		ipPrefix := ip.String() + "/" + strconv.Itoa(prefixLength)
		return ipPrefix, nil
	} else {
		return "", errors.New("infra needs a valid loopback ipv4 cidr")
	}
}

func getLoopbackIpv6(cr *infrav1alpha1.Infrastructure, index uint32) (string, error) {
	if cr.GetCidr() != nil && cr.GetLoopbackCidrIpv6() != "" {
		p, err := netaddr.ParseIPPrefix(cr.GetLoopbackCidrIpv6())
		if err != nil {
			return "", err
		}
		ip, err := GetIndexedIP(p.IPNet(), int(index))
		if err != nil {
			return "", err
		}
		prefixLength := 128
		ipPrefix := ip.String() + "/" + strconv.Itoa(prefixLength)
		return ipPrefix, nil
	} else {
		return "", errors.New("infra needs a valid loopback ipv6 cidr")
	}
}

func getAS(cr *infrav1alpha1.Infrastructure, index uint32) (uint32, error) {
	if cr.GetAsPool() != nil && cr.GetAsPoolStart() != 0 && cr.GetAsPoolEnd() != 0 {
		as := cr.GetAsPoolStart() + index
		if as > cr.GetAsPoolEnd() {
			return 0, errors.New("infra as pool is not big enough")
		}
		return as, nil
	}
	return 0, errors.New("infra as pool not assigned")
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
