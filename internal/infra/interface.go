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
	"strings"

	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/meta"
	"github.com/yndd/ndd-runtime/pkg/utils"
	networkv1alpha1 "github.com/yndd/ndda-network/apis/network/v1alpha1"
	"github.com/yndd/nddo-grpc/resource/resourcepb"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/odns"
	"github.com/yndd/nddo-runtime/pkg/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	InterfacePrefix = "infra"

	errCreateInterface = "cannot create Interface"
	errDeleteInterface = "cannot delete Interface"
	errGetInterface    = "cannot get Interface"
)

type InterfaceKind string

const (
	InterfaceKindLoopback   InterfaceKind = "loopback"
	InterfaceKindManagement InterfaceKind = "management"
	InterfaceKindInterface  InterfaceKind = "interface"
	InterfaceKindIrb        InterfaceKind = "irb"
	InterfaceKindVxlan      InterfaceKind = "vxlan"
	InterfaceKindSystem     InterfaceKind = "system"
)

func (s InterfaceKind) String() string {
	switch s {
	case InterfaceKindManagement:
		return "management"
	case InterfaceKindLoopback:
		return "loopback"
	case InterfaceKindInterface:
		return "interface"
	case InterfaceKindIrb:
		return "irb"
	case InterfaceKindVxlan:
		return "vxlan"
	case InterfaceKindSystem:
		return "system"
	}
	return "unknown"
}

// InfraOption is used to configure the Infra.
type InterfaceOption func(*itfce)

func WithInterfaceLogger(log logging.Logger) InterfaceOption {
	return func(r *itfce) {
		r.log = log
	}
}

func WithInterfaceK8sClient(c resource.ClientApplicator) InterfaceOption {
	return func(r *itfce) {
		r.client = c
	}
}

func WithInterfaceIpamClient(c resourcepb.ResourceClient) InterfaceOption {
	return func(r *itfce) {
		r.ipamClient = c
	}
}

func WithInterfaceAsPoolClient(c resourcepb.ResourceClient) InterfaceOption {
	return func(r *itfce) {
		r.aspoolClient = c
	}
}

func WithInterfaceNiRegisterClient(c resourcepb.ResourceClient) InterfaceOption {
	return func(r *itfce) {
		r.niregisterClient = c
	}
}

func NewInterface(n Node, name string, opts ...InterfaceOption) Interface {
	i := &itfce{
		name:          &name,
		node:          n,
		subInterfaces: make(map[string]SubInterface),
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ Interface = &itfce{}

type Interface interface {
	GetNode() Node
	GetName() string
	GetKind() string
	IsLag() bool
	IsLagMember() bool
	IsLacp() bool
	IsLacpFallback() bool
	GetLagName() string
	SetNode(Node)
	SetName(string)
	SetKind(InterfaceKind)
	SetLag()
	SetLagMember()
	SetLacp()
	SetLacpFallback()
	SetLagName(string)
	GetLagMembers() []Interface
	GetLagMemberNames() []string
	HasVlanTags() bool
	GetSubInterfaces() map[string]SubInterface

	GetNddaInterface(ctx context.Context, cr infrav1alpha1.If) (*string, error)
	CreateNddaInterface(ctx context.Context, cr infrav1alpha1.If) error
	DeleteNddaInterface(ctx context.Context, cr infrav1alpha1.If) error

	Print(string, int)
}

type itfce struct {
	//client client.Client
	client           resource.ClientApplicator
	ipamClient       resourcepb.ResourceClient
	aspoolClient     resourcepb.ResourceClient
	niregisterClient resourcepb.ResourceClient
	log              logging.Logger

	node          Node
	name          *string
	kind          InterfaceKind
	lag           *bool
	lagMember     *bool
	lagName       *string
	lacp          *bool
	lacpFallback  *bool
	subInterfaces map[string]SubInterface
}

func (x *itfce) GetNode() Node {
	return x.node
}

func (x *itfce) GetName() string {
	if reflect.ValueOf(x.name).IsZero() {
		return ""
	}
	return *x.name
}

func (x *itfce) GetKind() string {
	return string(x.kind)
}

func (x *itfce) IsLag() bool {
	if reflect.ValueOf(x.lag).IsZero() {
		return false
	}
	return *x.lag
}

func (x *itfce) IsLagMember() bool {
	if reflect.ValueOf(x.lagMember).IsZero() {
		return false
	}
	return *x.lagMember
}

func (x *itfce) IsLacp() bool {
	if reflect.ValueOf(x.lacp).IsZero() {
		return false
	}
	return *x.lacp
}

func (x *itfce) IsLacpFallback() bool {
	if reflect.ValueOf(x.lacpFallback).IsZero() {
		return false
	}
	return *x.lacpFallback
}

func (x *itfce) GetLagName() string {
	if reflect.ValueOf(x.lagName).IsZero() {
		return ""
	}
	return *x.lagName
}

func (x *itfce) SetNode(n Node) {
	x.node = n
}

func (x *itfce) SetName(n string) {
	x.name = &n
}

func (x *itfce) SetKind(n InterfaceKind) {
	x.kind = n
}

func (x *itfce) SetLag() {
	x.lag = utils.BoolPtr(true)
}

func (x *itfce) SetLagMember() {
	x.lagMember = utils.BoolPtr(true)
}

func (x *itfce) SetLacp() {
	x.lacp = utils.BoolPtr(true)
}

func (x *itfce) SetLacpFallback() {
	x.lacpFallback = utils.BoolPtr(true)
}

func (x *itfce) SetLagName(n string) {
	x.lagName = &n
}

func (x *itfce) GetLagMembers() []Interface {
	is := make([]Interface, 0)
	if *x.lagName != "" {
		for _, i := range x.node.GetInterfaces() {
			if i.IsLagMember() && i.GetLagName() == *x.lagName {
				is = append(is, i)
			}
		}
	}
	return is
}

func (x *itfce) GetLagMemberNames() []string {
	is := make([]string, 0)
	if *x.lagName != "" {
		for _, i := range x.node.GetInterfaces() {
			if i.IsLagMember() && i.GetLagName() == *x.lagName {
				is = append(is, i.GetName())
			}
		}
	}
	return is
}

func (x *itfce) GetSubInterfaces() map[string]SubInterface {
	return x.subInterfaces
}

func (x *itfce) HasVlanTags() bool {
	//for _, s := range x.subInterfaces {
	//
	//}
	return false
}

func (x *itfce) Print(itfceName string, n int) {
	fmt.Printf("%s Interface: %s Kind: %s LAG: %t, LAG Member: %t\n", strings.Repeat(" ", n), itfceName, x.GetKind(), x.IsLag(), x.IsLagMember())
	n++
	for subItfceName, i := range x.subInterfaces {
		i.Print(subItfceName, n)
	}
}

func (x *itfce) GetNddaInterface(ctx context.Context, cr infrav1alpha1.If) (*string, error) {
	o := x.buildNddaInterface(cr)
	if err := x.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(), Name: o.GetName()}, o); err != nil {
		return nil, errors.Wrap(err, errGetInterface)
	}
	return utils.StringPtr(o.GetName()), nil
}

func (x *itfce) CreateNddaInterface(ctx context.Context, cr infrav1alpha1.If) error {
	o := x.buildNddaInterface(cr)
	if err := x.client.Apply(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteInterface)
	}
	return nil
}

func (x *itfce) DeleteNddaInterface(ctx context.Context, cr infrav1alpha1.If) error {
	o := x.buildNddaInterface(cr)
	if err := x.client.Delete(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteInterface)
	}
	return nil
}

func (x *itfce) buildNddaInterface(cr infrav1alpha1.If) *networkv1alpha1.Interface {
	itfceName := strings.ReplaceAll(x.GetName(), "/", "-")

	//resourceName := odns.GetOdnsResourceName(cr.GetName(),
	//	[]string{cr.GetNetworkInstanceName()},
	//	[]string{x.GetNode().GetName(), itfceName, x.GetKind()})

	resourceName := odns.GetOdnsResourceName(cr.GetName(), strings.ToLower(infrav1alpha1.InfrastructureKindKind),
		[]string{x.GetNode().GetName(), itfceName, x.GetKind()})

	objMeta := metav1.ObjectMeta{
		//Name:      strings.Join([]string{cr.GetName(), cr.GetNetworkInstanceName(), x.GetNode().GetName(), itfceName, x.GetKind()}, "."),
		Name:      resourceName,
		Namespace: cr.GetNamespace(),
		Labels: map[string]string{
			networkv1alpha1.LabelInterfaceKindKey: x.GetKind(),
		},
		OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
	}

	switch x.GetKind() {
	case InterfaceKindInterface.String():
		return &networkv1alpha1.Interface{
			ObjectMeta: objMeta,
			Spec: networkv1alpha1.InterfaceSpec{
				NodeName: utils.StringPtr(x.GetNode().GetName()),
				//EndpointGroup: utils.StringPtr(cr.GetName()),
				Interface: &networkv1alpha1.NetworkInterface{
					Name:         utils.StringPtr(x.GetName()),
					Kind:         utils.StringPtr(x.GetKind()),
					Lag:          utils.BoolPtr(x.IsLag()),
					LagMember:    utils.BoolPtr(x.IsLagMember()),
					LagName:      utils.StringPtr(x.GetLagName()),
					Lacp:         utils.BoolPtr(x.IsLacp()),
					LacpFallback: utils.BoolPtr(x.IsLacpFallback()),
				},
			},
		}
	default:
		return &networkv1alpha1.Interface{
			ObjectMeta: objMeta,
			Spec: networkv1alpha1.InterfaceSpec{
				NodeName: utils.StringPtr(x.GetNode().GetName()),
				//EndpointGroup: utils.StringPtr(cr.GetName()),
				Interface: &networkv1alpha1.NetworkInterface{
					Name: utils.StringPtr(x.GetName()),
					Kind: utils.StringPtr(x.GetKind()),
				},
			},
		}
	}
}
*/
