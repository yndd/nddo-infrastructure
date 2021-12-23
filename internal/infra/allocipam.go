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
	"strings"

	"github.com/yndd/ndd-runtime/pkg/meta"
	"github.com/yndd/ndd-runtime/pkg/utils"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	ipamv1alpha1 "github.com/yndd/nddr-ipam/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	allocIpamPrefix = "alloc-ipam"

	errApplyAllocIpam            = "cannot apply ipam allocation"
	errDeleteAllocIpam           = "cannot delete ipam allocation"
	errGetAllocIpam              = "cannot get ipam allocation"
	errUnavailableIpamAllocation = "ipam allocation prefix unavailable"
)

// TODO:
// allocation per address family, prefix length will be determined by the as
// allocation per network instance -> tbd how we indentify this
// puprose, loopback need to be identified -> best in ipam

type IpamOptions struct {
	NetworkInstance string
	AddressFamily   string
	IpPrefix        string
	EpIndex         int
}

func buildIpamAllocLoopback(cr infrav1alpha1.If, x topov1alpha1.Tn, ipamOptions *IpamOptions) *ipamv1alpha1.Alloc {
	/*
		var prefixlength uint32
		if ipamOptions.AddressFamily == string(ipamv1alpha1.AddressFamilyIpv4) {
			prefixlength = 32
		}
		if ipamOptions.AddressFamily == string(ipamv1alpha1.AddressFamilyIpv6) {
			prefixlength = 128
		}
	*/
	return &ipamv1alpha1.Alloc{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName(), ipamOptions.AddressFamily}, "-"),
			Namespace: cr.GetNamespace(),
			Labels: map[string]string{
				labelPrefix: strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName()}, "-"),
			},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: ipamv1alpha1.AllocSpec{
			IpamName:            utils.StringPtr(cr.GetLoopbackIpamPool()),
			NetworkInstanceName: utils.StringPtr(ipamOptions.NetworkInstance),
			Alloc: &ipamv1alpha1.IpamAlloc{
				//AddressFamily: utils.StringPtr(ipamOptions.AddressFamily),
				//PrefixLength: utils.Uint32Ptr(prefixlength),
				Selector: []*ipamv1alpha1.IpamAllocSelectorTag{
					{Key: utils.StringPtr(ipamv1alpha1.KeyAddressFamily), Value: utils.StringPtr(ipamOptions.AddressFamily)},
					{Key: utils.StringPtr(ipamv1alpha1.KeyPurpose), Value: utils.StringPtr(ipamv1alpha1.PurposeLoopback.String())},
				},
				SourceTag: []*ipamv1alpha1.IpamAllocSourceTagTag{
					{Key: utils.StringPtr(topov1alpha1.KeyNode), Value: utils.StringPtr(x.GetName())},
				},
			},
		},
	}
}

// TODO:
// allocation per address family, prefix length will be determined by the af and other input
// allocation per network instance -> tbd how we indentify this
// puprose, isl need to be identified -> best in ipam

func buildIpamAllocLink(cr infrav1alpha1.If, x topov1alpha1.Tl, ipamOptions *IpamOptions) *ipamv1alpha1.Alloc {
	/*
		var prefixlength uint32
		if ipamOptions.AddressFamily == string(ipamv1alpha1.AddressFamilyIpv4) {
			prefixlength = 31
		}
		if ipamOptions.AddressFamily == string(ipamv1alpha1.AddressFamilyIpv6) {
			prefixlength = 127
		}
	*/
	return &ipamv1alpha1.Alloc{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName(), ipamOptions.AddressFamily}, "-"),
			Namespace: cr.GetNamespace(),
			Labels: map[string]string{
				labelPrefix: strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName()}, "-"),
			},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: ipamv1alpha1.AllocSpec{
			IpamName:            utils.StringPtr(cr.GetLoopbackIpamPool()),
			NetworkInstanceName: utils.StringPtr(ipamOptions.NetworkInstance),
			Alloc: &ipamv1alpha1.IpamAlloc{
				//AddressFamily: utils.StringPtr(ipamOptions.AddressFamily),
				//PrefixLength: utils.Uint32Ptr(prefixlength),
				Selector: []*ipamv1alpha1.IpamAllocSelectorTag{
					{Key: utils.StringPtr(ipamv1alpha1.KeyAddressFamily), Value: utils.StringPtr(ipamOptions.AddressFamily)},
					{Key: utils.StringPtr(ipamv1alpha1.KeyPurpose), Value: utils.StringPtr(ipamv1alpha1.PurposeIsl.String())},
				},
				SourceTag: []*ipamv1alpha1.IpamAllocSourceTagTag{
					{Key: utils.StringPtr(x.GetEndpointANodeName()), Value: utils.StringPtr(x.GetEndpointAInterfaceName())},
					{Key: utils.StringPtr(x.GetEndpointBNodeName()), Value: utils.StringPtr(x.GetEndpointBInterfaceName())},
				},
			},
		},
	}
}

func buildIpamAllocEndPoint(cr infrav1alpha1.If, x topov1alpha1.Tl, ipamOptions *IpamOptions) *ipamv1alpha1.Alloc {
	var (
		nodeName  string
		itfcename string
	)
	if ipamOptions.EpIndex == 0 {
		nodeName = x.GetEndpointANodeName()
		itfcename = x.GetEndpointAInterfaceName()
	} else {
		nodeName = x.GetEndpointBNodeName()
		itfcename = x.GetEndpointBInterfaceName()
	}
	return &ipamv1alpha1.Alloc{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName(), nodeName, ipamOptions.AddressFamily}, "-"),
			Namespace: cr.GetNamespace(),
			Labels:    map[string]string{
				//labelPrefix: strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName(), nodeName}, "-"),
			},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: ipamv1alpha1.AllocSpec{
			IpamName:            utils.StringPtr(cr.GetLoopbackIpamPool()),
			NetworkInstanceName: utils.StringPtr(ipamOptions.NetworkInstance),
			Alloc: &ipamv1alpha1.IpamAlloc{
				//AddressFamily: utils.StringPtr(ipamOptions.AddressFamily),
				IpPrefix: utils.StringPtr(ipamOptions.IpPrefix),
				Selector: []*ipamv1alpha1.IpamAllocSelectorTag{
					{Key: utils.StringPtr(ipamv1alpha1.KeyAddressFamily), Value: utils.StringPtr(ipamOptions.AddressFamily)},
					{Key: utils.StringPtr(ipamv1alpha1.KeyPurpose), Value: utils.StringPtr(ipamv1alpha1.PurposeIsl.String())},
					{Key: utils.StringPtr(x.GetEndpointANodeName()), Value: utils.StringPtr(x.GetEndpointAInterfaceName())},
					{Key: utils.StringPtr(x.GetEndpointBNodeName()), Value: utils.StringPtr(x.GetEndpointBInterfaceName())},
				},
				SourceTag: []*ipamv1alpha1.IpamAllocSourceTagTag{
					{Key: utils.StringPtr(topov1alpha1.KeyNode), Value: utils.StringPtr(nodeName)},
					{Key: utils.StringPtr(topov1alpha1.KeyInterface), Value: utils.StringPtr(itfcename)},
				},
			},
		},
	}
}
