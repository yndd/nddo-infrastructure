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
	"context"
	"strings"

	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/utils"
	"github.com/yndd/nddo-grpc/resource/resourcepb"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/odns"
	"github.com/yndd/nddo-runtime/pkg/resource"
	ipamv1alpha1 "github.com/yndd/nddr-ipam-registry/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// InfraOption is used to configure the Infra.
type LinkOption func(*link)

func WithLinkLogger(log logging.Logger) LinkOption {
	return func(r *link) {
		r.log = log
	}
}

func WithLinkK8sClient(c resource.ClientApplicator) LinkOption {
	return func(r *link) {
		r.client = c
	}
}

func WithLinkIpamClient(c resourcepb.ResourceClient) LinkOption {
	return func(r *link) {
		r.ipamClient = c
	}
}

func WithLinkAsPoolClient(c resourcepb.ResourceClient) LinkOption {
	return func(r *link) {
		r.aspoolClient = c
	}
}

func WithLinkNiRegisterClient(c resourcepb.ResourceClient) LinkOption {
	return func(r *link) {
		r.niregisterClient = c
	}
}

func NewLink(n string, opts ...LinkOption) Link {
	i := &link{
		name:       &n,
		nodeNames:  make(map[int]string),
		itfceNames: make(map[int]string),
		ipv4:       make(map[string]AddressInfo),
		ipv6:       make(map[string]AddressInfo),
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ Link = &link{}

type Link interface {
	GetName() string
	GetNodeNames() map[int]string
	GetInterfaceNames() map[int]string
	GetNodeName(int) string
	GetInterfaceName(int) string
	GetPrefix(string) string
	SetPrefix(string, string)
	SetNodeName(int, string)
	SetInterfaceName(int, string)
	AllocateIPLink(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error
	DeAllocateIPLink(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error
	ValidateIPLink(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) (*string, error)
	AllocateIPLinkEndpoint(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error
	DeAllocateIPLinkEndpoint(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error
	ValidateIPLinkEndpoint(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) (*string, error)

	GrpcAllocateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) (*string, error)
	GrpcDeAllocateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error
	GrpcAllocateEndpointIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) (*string, error)
	GrpcDeAllocateEndpointIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error
}

type link struct {
	client           resource.ClientApplicator
	ipamClient       resourcepb.ResourceClient
	aspoolClient     resourcepb.ResourceClient
	niregisterClient resourcepb.ResourceClient
	//client client.Client
	log logging.Logger

	name       *string
	nodeNames  map[int]string
	itfceNames map[int]string
	ipv4       map[string]AddressInfo
	ipv6       map[string]AddressInfo
}

func (x *link) GetName() string {
	return *x.name
}

func (x *link) GetNodeNames() map[int]string {
	return x.nodeNames
}

func (x *link) GetInterfaceNames() map[int]string {
	return x.itfceNames
}

func (x *link) GetNodeName(idx int) string {
	if nodeName, ok := x.nodeNames[idx]; ok {
		return nodeName
	}
	return ""
}

func (x *link) GetInterfaceName(idx int) string {
	if itfceName, ok := x.itfceNames[idx]; ok {
		return itfceName
	}
	return ""
}

func (x *link) GetPrefix(af string) string {
	switch af {
	case ipamv1alpha1.AddressFamilyIpv4.String():
		for prefix := range x.ipv4 {
			return prefix
		}
	case ipamv1alpha1.AddressFamilyIpv6.String():
		for prefix := range x.ipv6 {
			return prefix
		}
	}
	return ""
}

func (x *link) SetPrefix(af, p string) {
	switch af {
	case ipamv1alpha1.AddressFamilyIpv4.String():
		x.ipv4[p] = NewAddressInfo()
	case ipamv1alpha1.AddressFamilyIpv6.String():
		x.ipv6[p] = NewAddressInfo()
	}
}

func (x *link) SetNodeName(idx int, s string) {
	x.nodeNames[idx] = s
}

func (x *link) SetInterfaceName(idx int, s string) {
	x.itfceNames[idx] = s
}

func (x *link) GrpcAllocateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) (*string, error) {
	req := buildGrpcAllocateLinkIP(cr, tl, ipamOptions)
	reply, err := x.ipamClient.ResourceRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if !reply.Ready {
		return nil, errors.New("grppc ipam allocation server not ready")
	}
	if ipprefix, ok := reply.Data["ip-prefix"]; ok {
		ipprefixVal, err := GetValue(ipprefix)
		if err != nil {
			return nil, err
		}
		switch ipPrefix := ipprefixVal.(type) {
		case string:
			return utils.StringPtr(ipPrefix), nil
		default:
			return nil, errors.New("wrong return data for ipam alocation")
		}

	}
	return nil, nil
}

func (x *link) GrpcDeAllocateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error {
	req := buildGrpcAllocateLinkIP(cr, tl, ipamOptions)
	_, err := x.ipamClient.ResourceRelease(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (x *link) AllocateIPLink(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error {
	o := buildIpamAllocLink(cr, tl, ipamOptions)
	if err := x.client.Apply(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteAllocIpam)
	}
	return nil
}

func (x *link) DeAllocateIPLink(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error {
	o := buildIpamAllocLink(cr, tl, ipamOptions)
	if err := x.client.Delete(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteAllocIpam)
	}
	return nil
}

func (x *link) ValidateIPLink(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) (*string, error) {
	o := buildIpamAllocLink(cr, tl, ipamOptions)
	if err := x.client.Get(ctx, types.NamespacedName{Namespace: cr.GetNamespace(), Name: o.GetName()}, o); err != nil {
		return nil, errors.Wrap(err, errGetAllocIpam)
	}
	if o.GetCondition(ipamv1alpha1.ConditionKindReady).Status == corev1.ConditionTrue {
		if prefix, ok := o.HasIpPrefix(); ok {
			return &prefix, nil
		}
		x.log.Debug("strange ipam alloc ready but no Ip prefix allocated")
		return nil, errors.Errorf("%s: %s", errUnavailableIpamAllocation, "strange ipam alloc ready but no Ip prefix allocated")
	}
	return nil, errors.Errorf("%s: %s", errUnavailableIpamAllocation, o.GetCondition(ipamv1alpha1.ConditionKindReady).Message)
}

func (x *link) GrpcAllocateEndpointIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) (*string, error) {
	req := buildGrpcAllocateEndPointIP(cr, tl, ipamOptions)
	reply, err := x.ipamClient.ResourceRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if !reply.Ready {
		return nil, errors.New("grppc ipam allocation server not ready")
	}
	if ipprefix, ok := reply.Data["ip-prefix"]; ok {
		ipprefixVal, err := GetValue(ipprefix)
		if err != nil {
			return nil, err
		}
		switch ipPrefix := ipprefixVal.(type) {
		case string:
			return utils.StringPtr(ipPrefix), nil
		default:
			return nil, errors.New("wrong return data for ipam alocation")
		}

	}
	return nil, nil
}

func (x *link) GrpcDeAllocateEndpointIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error {
	req := buildGrpcAllocateEndPointIP(cr, tl, ipamOptions)
	_, err := x.ipamClient.ResourceRelease(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (x *link) AllocateIPLinkEndpoint(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error {
	o := buildIpamAllocEndPoint(cr, tl, ipamOptions)
	if err := x.client.Apply(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteAllocIpam)
	}
	return nil
}

func (x *link) DeAllocateIPLinkEndpoint(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) error {
	o := buildIpamAllocEndPoint(cr, tl, ipamOptions)
	if err := x.client.Delete(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteAllocIpam)
	}
	return nil
}

func (x *link) ValidateIPLinkEndpoint(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl, ipamOptions *IpamOptions) (*string, error) {
	o := buildIpamAllocEndPoint(cr, tl, ipamOptions)
	if err := x.client.Get(ctx, types.NamespacedName{Namespace: cr.GetNamespace(), Name: o.GetName()}, o); err != nil {
		return nil, errors.Wrap(err, errGetAllocIpam)
	}
	if o.GetCondition(ipamv1alpha1.ConditionKindReady).Status == corev1.ConditionTrue {
		if prefix, ok := o.HasIpPrefix(); ok {
			return &prefix, nil
		}
		x.log.Debug("strange ipam alloc ready but no Ip prefix allocated")
		return nil, errors.Errorf("%s: %s", errUnavailableIpamAllocation, "strange ipam alloc ready but no Ip prefix allocated")
	}
	return nil, errors.Errorf("%s: %s", errUnavailableIpamAllocation, o.GetCondition(ipamv1alpha1.ConditionKindReady).Message)
}

func buildGrpcAllocateLinkIP(cr infrav1alpha1.If, x topov1alpha1.Tl, ipamOptions *IpamOptions) *resourcepb.Request {

	registerName := odns.GetOdnsRegisterName(cr.GetName(),
		[]string{strings.ToLower(infrav1alpha1.InfrastructureKindKind), ipamOptions.RegistryName, ipamOptions.NetworkInstanceName},
		[]string{x.GetLinkName(), ipamOptions.AddressFamily})

	return &resourcepb.Request{
		//Oda:                 oda,
		Namespace:    cr.GetNamespace(),
		RegisterName: registerName,
		//RegistryName:        ipamOptions.RegistryName,
		//NetworkInstanceName: ipamOptions.NetworkInstanceName,
		//Name:                strings.Join([]string{cr.GetName(), x.GetLinkName(), ipamOptions.AddressFamily}, "."),
		Kind: "ipam",
		Request: &resourcepb.Req{
			Selector: map[string]string{
				ipamv1alpha1.KeyAddressFamily: ipamOptions.AddressFamily,
				ipamv1alpha1.KeyPurpose:       ipamv1alpha1.PurposeIsl.String(),
			},
			SourceTag: map[string]string{
				x.GetEndpointANodeName(): x.GetEndpointAInterfaceName(),
				x.GetEndpointBNodeName(): x.GetEndpointBInterfaceName(),
			},
		},
	}
}


func buildGrpcAllocateEndPointIP(cr infrav1alpha1.If, x topov1alpha1.Tl, ipamOptions *IpamOptions) *resourcepb.Request {
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
		[]string{strings.ToLower(infrav1alpha1.InfrastructureKindKind), ipamOptions.RegistryName, ipamOptions.NetworkInstanceName},
		[]string{x.GetLinkName(), nodeName, ipamOptions.AddressFamily})

	return &resourcepb.Request{
		Namespace:    cr.GetNamespace(),
		RegisterName: registerName,
		Kind:         "ipam",
		Request: &resourcepb.Req{
			IpPrefix: ipamOptions.IpPrefix,
			Selector: map[string]string{
				ipamv1alpha1.KeyAddressFamily: ipamOptions.AddressFamily,
				ipamv1alpha1.KeyPurpose:       ipamv1alpha1.PurposeIsl.String(),
				x.GetEndpointANodeName():      x.GetEndpointAInterfaceName(),
				x.GetEndpointBNodeName():      x.GetEndpointBInterfaceName(),
			},
			SourceTag: map[string]string{
				topov1alpha1.KeyNode:      nodeName,
				topov1alpha1.KeyInterface: itfcename,
			},
		},
	}
}
*/
