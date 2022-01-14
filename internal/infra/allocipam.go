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

/*
import (
	"strings"

	"github.com/yndd/ndd-runtime/pkg/meta"
	"github.com/yndd/ndd-runtime/pkg/utils"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	nddov1 "github.com/yndd/nddo-runtime/apis/common/v1"
	"github.com/yndd/nddo-runtime/pkg/odns"
	ipamv1alpha1 "github.com/yndd/nddr-ipam-registry/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	errUnavailableIpamAllocation = "ipam allocation prefix unavailable"
)

// TODO:
// allocation per address family, prefix length will be determined by the as
// allocation per network instance -> tbd how we indentify this
// puprose, loopback need to be identified -> best in ipam

type IpamOptions struct {
	RegistryName        string
	NetworkInstanceName string
	AddressFamily       string
	IpPrefix            string
	EpIndex             int
}

func buildIpamAllocLoopback(cr infrav1alpha1.If, x topov1alpha1.Tn, ipamOptions *IpamOptions) *ipamv1alpha1.Register {

	registerName := odns.GetOdnsRegisterName(cr.GetName(),
		[]string{strings.ToLower(cr.GetObjectKind().GroupVersionKind().Kind), ipamOptions.RegistryName, ipamOptions.NetworkInstanceName},
		[]string{x.GetNodeName(), ipamOptions.AddressFamily})

	return &ipamv1alpha1.Register{
		ObjectMeta: metav1.ObjectMeta{
			Name:      registerName,
			Namespace: cr.GetNamespace(),
			//Labels: map[string]string{
			//	labelPrefix: strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName()}, "-"),
			//},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: ipamv1alpha1.RegisterSpec{
			//RegistryName:        &ipamOptions.RegistryName,
			//NetworkInstanceName: &ipamOptions.NetworkInstanceName,
			Register: &ipamv1alpha1.IpamRegister{
				Selector: []*nddov1.Tag{
					{Key: utils.StringPtr(ipamv1alpha1.KeyAddressFamily), Value: utils.StringPtr(ipamOptions.AddressFamily)},
					{Key: utils.StringPtr(ipamv1alpha1.KeyPurpose), Value: utils.StringPtr(ipamv1alpha1.PurposeLoopback.String())},
				},
				SourceTag: []*nddov1.Tag{
					{Key: utils.StringPtr(topov1alpha1.KeyNode), Value: utils.StringPtr(x.GetName())},
				},
			},
		},
	}
	//r.Spec.Oda = cr.GetOda().Oda
	//return r
}

func buildIpamAllocLink(cr infrav1alpha1.If, x topov1alpha1.Tl, ipamOptions *IpamOptions) *ipamv1alpha1.Register {

	registerName := odns.GetOdnsRegisterName(cr.GetName(),
		[]string{strings.ToLower(cr.GetObjectKind().GroupVersionKind().Kind), ipamOptions.RegistryName, ipamOptions.NetworkInstanceName},
		[]string{x.GetLinkName(), ipamOptions.AddressFamily})

	return &ipamv1alpha1.Register{
		ObjectMeta: metav1.ObjectMeta{
			Name:      registerName,
			Namespace: cr.GetNamespace(),
			//Labels: map[string]string{
			//	labelPrefix: strings.Join([]string{ipamOptions.IpamName, ipamOptions.NetworkInstanceName, x.GetLinkName(), ipamOptions.AddressFamily}, "."),
			//},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: ipamv1alpha1.RegisterSpec{
			//RegistryName:        &ipamOptions.RegistryName,
			//NetworkInstanceName: &ipamOptions.NetworkInstanceName,
			Register: &ipamv1alpha1.IpamRegister{
				Selector: []*nddov1.Tag{
					{Key: utils.StringPtr(ipamv1alpha1.KeyAddressFamily), Value: utils.StringPtr(ipamOptions.AddressFamily)},
					{Key: utils.StringPtr(ipamv1alpha1.KeyPurpose), Value: utils.StringPtr(ipamv1alpha1.PurposeIsl.String())},
				},
				SourceTag: []*nddov1.Tag{
					{Key: utils.StringPtr(x.GetEndpointANodeName()), Value: utils.StringPtr(x.GetEndpointAInterfaceName())},
					{Key: utils.StringPtr(x.GetEndpointBNodeName()), Value: utils.StringPtr(x.GetEndpointBInterfaceName())},
				},
			},
		},
	}
	//r.Spec.Oda = cr.GetOda().Oda
	//return r
}

func buildIpamAllocEndPoint(cr infrav1alpha1.If, x topov1alpha1.Tl, ipamOptions *IpamOptions) *ipamv1alpha1.Register {
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

	registerName := odns.GetOdnsRegisterName(cr.GetName(),
		[]string{strings.ToLower(cr.GetObjectKind().GroupVersionKind().Kind), ipamOptions.RegistryName, ipamOptions.NetworkInstanceName},
		[]string{x.GetLinkName(), ipamOptions.AddressFamily})

	return &ipamv1alpha1.Register{
		ObjectMeta: metav1.ObjectMeta{
			Name:      registerName,
			Namespace: cr.GetNamespace(),
			Labels:    map[string]string{
				//labelPrefix: strings.Join([]string{allocIpamPrefix, cr.GetName(), x.GetName(), nodeName}, "-"),
			},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: ipamv1alpha1.RegisterSpec{
			//RegistryName:        &ipamOptions.RegistryName,
			//NetworkInstanceName: &ipamOptions.NetworkInstanceName,
			Register: &ipamv1alpha1.IpamRegister{
				IpPrefix: utils.StringPtr(ipamOptions.IpPrefix),
				Selector: []*nddov1.Tag{
					{Key: utils.StringPtr(ipamv1alpha1.KeyAddressFamily), Value: utils.StringPtr(ipamOptions.AddressFamily)},
					{Key: utils.StringPtr(ipamv1alpha1.KeyPurpose), Value: utils.StringPtr(ipamv1alpha1.PurposeIsl.String())},
					{Key: utils.StringPtr(x.GetEndpointANodeName()), Value: utils.StringPtr(x.GetEndpointAInterfaceName())},
					{Key: utils.StringPtr(x.GetEndpointBNodeName()), Value: utils.StringPtr(x.GetEndpointBInterfaceName())},
				},
				SourceTag: []*nddov1.Tag{
					{Key: utils.StringPtr(topov1alpha1.KeyNode), Value: utils.StringPtr(nodeName)},
					{Key: utils.StringPtr(topov1alpha1.KeyInterface), Value: utils.StringPtr(itfcename)},
				},
			},
		},
	}
	//r.Spec.Oda = cr.GetOda().Oda
	//return r
}
*/
