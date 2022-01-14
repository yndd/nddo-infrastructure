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
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/utils"
	"github.com/yndd/nddo-grpc/resource/resourcepb"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/odns"
	"github.com/yndd/nddo-runtime/pkg/resource"
	asv1alpha1 "github.com/yndd/nddr-as-registry/apis/as/v1alpha1"
	ipamv1alpha1 "github.com/yndd/nddr-ipam-registry/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	errCreateAllocAS = "cannot create allocAS"
	errGetAllocAS    = "cannot delete allocAS"
	errDeleteAllocAS = "cannot get allocAS"
	errUpdateAllocAS = "cannot get allocAS"

	errCreateAllocIpam = "cannot create allocIpam"
	errGetAllocIpam    = "cannot delete allocIpam"
	errDeleteAllocIpam = "cannot get allocIpam"
	errUpdateAllocIpam = "cannot get allocIpam"
)

type NodeKind string

const (
	NodeKindSRL  NodeKind = "srl"
	NodeKindSROS NodeKind = "sros"
)

func (s NodeKind) String() string {
	switch s {
	case NodeKindSRL:
		return "srl"
	case NodeKindSROS:
		return "sros"
	}
	return "srl"
}

// InfraOption is used to configure the Infra.
type NodeOption func(*node)

func WithNodeLogger(log logging.Logger) NodeOption {
	return func(r *node) {
		r.log = log
	}
}

func WithNodeK8sClient(c resource.ClientApplicator) NodeOption {
	return func(r *node) {
		r.client = c
	}
}

func WithNodeIpamClient(c resourcepb.ResourceClient) NodeOption {
	return func(r *node) {
		r.ipamClient = c
	}
}

func WithNodeAsPoolClient(c resourcepb.ResourceClient) NodeOption {
	return func(r *node) {
		r.aspoolClient = c
	}
}

func WithNodeNiRegisterClient(c resourcepb.ResourceClient) NodeOption {
	return func(r *node) {
		r.niregisterClient = c
	}
}

func NewNode(n string, opts ...NodeOption) Node {
	i := &node{
		name:   &n,
		itfces: make(map[string]Interface),
		nis:    make(map[string]Ni),
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ Node = &node{}

type Node interface {
	Lock()
	UnLock()
	GetName() string
	GetIndex() uint32
	GetKind() string
	GetPlatform() string
	GetAS() uint32
	SetName(string)
	SetIndex(uint32)
	SetKind(string)
	SetPlatform(string)
	SetAS(uint32)
	GetInterfaces() map[string]Interface
	GetNis() map[string]Ni
	AllocateAS(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tn, asPoolName string) error
	DeAllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) error
	ValidateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) (*uint32, error)
	AllocateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) error
	DeAllocateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) error
	ValidateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) (*string, error)

	GrpcAllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) (*uint32, error)
	GrpcDeAllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) error
	GrpcAllocateLoopback(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) (*string, error)
	GrpcDeAllocateLoopback(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) error
	Print(string, int)
}

type node struct {
	client           resource.ClientApplicator
	ipamClient       resourcepb.ResourceClient
	aspoolClient     resourcepb.ResourceClient
	niregisterClient resourcepb.ResourceClient
	//client client.Client
	log logging.Logger

	name     *string
	index    *uint32
	kind     NodeKind
	platform *string
	as       *uint32
	itfces   map[string]Interface
	nis      map[string]Ni

	mutex sync.Mutex
}

func (x *node) Lock() {
	x.mutex.Lock()
}

func (x *node) UnLock() {
	x.mutex.Unlock()
}

func (x *node) GetName() string {
	if reflect.ValueOf(x.name).IsZero() {
		return ""
	}
	return *x.name
}

func (x *node) GetIndex() uint32 {
	if reflect.ValueOf(x.index).IsZero() {
		return 0
	}
	return *x.index
}

func (x *node) GetKind() string {
	return x.kind.String()
}

func (x *node) GetPlatform() string {
	if reflect.ValueOf(x.platform).IsZero() {
		return ""
	}
	return *x.platform
}

func (x *node) GetAS() uint32 {
	if reflect.ValueOf(x.as).IsZero() {
		return 0
	}
	return *x.as
}

func (x *node) SetName(n string) {
	x.name = &n
}

func (x *node) SetIndex(i uint32) {
	x.index = &i
}

func (x *node) SetKind(n string) {
	x.kind = NodeKind(n)
}

func (x *node) SetPlatform(p string) {
	x.platform = &p
}

func (x *node) SetAS(as uint32) {
	x.as = &as
}

func (x *node) GetInterfaces() map[string]Interface {
	return x.itfces
}

func (x *node) GetNis() map[string]Ni {
	return x.nis
}

func (x *node) GrpcAllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) (*uint32, error) {
	req := buildGrpcAllocateAsByIndex(cr, tn, asPoolName)
	reply, err := x.aspoolClient.ResourceRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if !reply.Ready {
		return nil, errors.New("grppc as pool allocation server not ready")
	}
	x.log.Debug("GrpcAllocateAS", "data", reply.Data)
	if as, ok := reply.Data["as"]; ok {
		asVal, err := GetValue(as)
		if err != nil {
			return nil, err
		}
		switch as := asVal.(type) {
		case string:
			a, err := strconv.Atoi(as)
			if err != nil {
				return nil, err
			}
			return utils.Uint32Ptr(uint32(a)), nil
		default:
			return nil, errors.New("wrong return data for as alocation")
		}

	}
	return nil, errors.New("no data found in as allocation")
}

func (x *node) GrpcDeAllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) error {
	req := buildGrpcAllocateAsByIndex(cr, tn, asPoolName)
	_, err := x.aspoolClient.ResourceRelease(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (x *node) GrpcAllocateLoopback(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) (*string, error) {
	req := buildGrpcAllocateLoopbackIP(cr, tn, ipamOptions)
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
	return nil, errors.New("no data found in ip loopback allocation")
}

func (x *node) GrpcDeAllocateLoopback(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) error {
	req := buildGrpcAllocateLoopbackIP(cr, tn, ipamOptions)
	_, err := x.ipamClient.ResourceRelease(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (x *node) AllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) error {
	o := buildAsPoolAllocByIndex(cr, tn, asPoolName)
	if err := x.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(), Name: o.GetName()}, o); err != nil {
		if resource.IgnoreNotFound(err) != nil {
			return errors.Wrap(err, errGetAllocAS)
		}
		if err := x.client.Create(ctx, o); err != nil {
			return errors.Wrap(err, errCreateAllocAS)
		}
	}
	if err := x.client.Update(ctx, o); err != nil {
		return errors.Wrap(err, errUpdateAllocAS)
	}

	return nil
}

func (x *node) DeAllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) error {
	o := buildAsPoolAllocByIndex(cr, tn, asPoolName)
	if err := x.client.Delete(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteAllocAS)
	}
	return nil
}

func (x *node) ValidateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, asPoolName string) (*uint32, error) {
	o := buildAsPoolAllocByIndex(cr, tn, asPoolName)
	if err := x.client.Get(ctx, types.NamespacedName{Namespace: cr.GetNamespace(), Name: o.GetName()}, o); err != nil {
		return nil, errors.Wrap(err, errGetAllocAS)
	}
	if o.GetCondition(asv1alpha1.ConditionKindReady).Status == corev1.ConditionTrue {
		if as, ok := o.HasAs(); ok {
			return &as, nil
		}
		x.log.Debug("strange AS alloc ready but no Ip prefix allocated")
		return nil, errors.Errorf("%s: %s", errUnavailableIpamAllocation, "strange AS alloc ready but no Ip prefix allocated")
	}
	return nil, errors.Errorf("%s: %s", errUnavailableAsPoolAllocation, o.GetCondition(asv1alpha1.ConditionKindReady).Message)
}

func (x *node) AllocateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) error {
	o := buildIpamAllocLoopback(cr, tn, ipamOptions)
	if err := x.client.Apply(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteAllocIpam)
	}
	return nil
}

func (x *node) DeAllocateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) error {
	o := buildIpamAllocLoopback(cr, tn, ipamOptions)
	if err := x.client.Delete(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteAllocIpam)
	}
	return nil
}

func (x *node) ValidateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn, ipamOptions *IpamOptions) (*string, error) {
	o := buildIpamAllocLoopback(cr, tn, ipamOptions)
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

func (x *node) Print(nodeName string, n int) {
	fmt.Printf("%s Node Name: %s Kind: %s AS: %d\n", nodeName, strings.Repeat(" ", n), x.GetKind(), x.GetAS())
	n++
	for itfceName, i := range x.itfces {
		i.Print(itfceName, n)
	}
	for niName, ni := range x.nis {
		ni.Print(niName, n)
	}
}

func buildGrpcAllocateAsByIndex(cr infrav1alpha1.If, x topov1alpha1.Tn, asRegistry string) *resourcepb.Request {

	registerName := odns.GetOdnsRegisterName(cr.GetName(),
		[]string{strings.ToLower(infrav1alpha1.InfrastructureKindKind), asRegistry},
		[]string{x.GetNodeName()})

	return &resourcepb.Request{
		//Oda:          oda,
		Namespace:    cr.GetNamespace(),
		RegisterName: registerName,
		//RegistryName: asRegistry,
		//Name:         strings.Join([]string{cr.GetName(), x.GetNodeName()}, "."),
		Kind: "as",
		Request: &resourcepb.Req{
			Selector: map[string]string{
				topov1alpha1.KeyNodeIndex: strconv.Itoa(int(x.GetNodeIndex())),
			},
			SourceTag: map[string]string{
				topov1alpha1.KeyNode: x.GetName(),
			},
		},
	}
}

func buildGrpcAllocateLoopbackIP(cr infrav1alpha1.If, x topov1alpha1.Tn, ipamOptions *IpamOptions) *resourcepb.Request {

	registerName := odns.GetOdnsRegisterName(cr.GetName(),
		[]string{strings.ToLower(infrav1alpha1.InfrastructureKindKind), ipamOptions.RegistryName, ipamOptions.NetworkInstanceName},
		[]string{x.GetNodeName()})

	return &resourcepb.Request{
		//Oda:                 oda,
		Namespace:    cr.GetNamespace(),
		RegisterName: registerName,
		//RegistryName:        ipamOptions.RegistryName,
		//NetworkInstanceName: ipamOptions.NetworkInstanceName,
		//Name:                strings.Join([]string{cr.GetName(), x.GetNodeName()}, "."),
		//Kind:                "ipam",
		Request: &resourcepb.Req{
			Selector: map[string]string{
				ipamv1alpha1.KeyAddressFamily: ipamOptions.AddressFamily,
				ipamv1alpha1.KeyPurpose:       ipamv1alpha1.PurposeLoopback.String(),
			},
			SourceTag: map[string]string{
				topov1alpha1.KeyNode: x.GetName(),
			},
		},
	}
}
*/
