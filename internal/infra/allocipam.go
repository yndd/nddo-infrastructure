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

func buildIpamAllocLoopback(cr infrav1alpha1.If, x topov1alpha1.Tn) *ipamv1alpha1.Alloc {
	return &ipamv1alpha1.Alloc{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName()}, "-"),
			Namespace: cr.GetNamespace(),
			Labels: map[string]string{
				labelPrefix: strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName()}, "-"),
			},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: ipamv1alpha1.AllocSpec{
			IpamName:            utils.StringPtr(cr.GetLoopbackIpamPool()),
			NetworkInstanceName: utils.StringPtr("default"),
			Alloc: &ipamv1alpha1.IpamAlloc{
				AddressFamily: utils.StringPtr("ipv4"),
				PrefixLength:  utils.Uint32Ptr(32),
				Selector: []*ipamv1alpha1.IpamAllocSelectorTag{
					{Key: utils.StringPtr("purpose"), Value: utils.StringPtr("loopback")},
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

func buildIpamAllocLink(cr infrav1alpha1.If, x topov1alpha1.Tl) *ipamv1alpha1.Alloc {
	return &ipamv1alpha1.Alloc{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName()}, "-"),
			Namespace: cr.GetNamespace(),
			Labels: map[string]string{
				labelPrefix: strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName()}, "-"),
			},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: ipamv1alpha1.AllocSpec{
			IpamName:            utils.StringPtr(cr.GetLoopbackIpamPool()),
			NetworkInstanceName: utils.StringPtr("default"),
			Alloc: &ipamv1alpha1.IpamAlloc{
				AddressFamily: utils.StringPtr("ipv4"),
				PrefixLength:  utils.Uint32Ptr(31),
				Selector: []*ipamv1alpha1.IpamAllocSelectorTag{
					{Key: utils.StringPtr("purpose"), Value: utils.StringPtr("isl")},
				},
				SourceTag: []*ipamv1alpha1.IpamAllocSourceTagTag{
					{Key: utils.StringPtr(topov1alpha1.KeyNode), Value: utils.StringPtr(x.GetName())},
				},
			},
		},
	}
}
