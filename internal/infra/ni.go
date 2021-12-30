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
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/meta"
	"github.com/yndd/ndd-runtime/pkg/utils"
	networkv1alpha1 "github.com/yndd/ndda-network/apis/network/v1alpha1"
	"github.com/yndd/nddo-grpc/resource/resourcepb"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/resource"
	aspoolv1alpha1 "github.com/yndd/nddr-as-pool/apis/aspool/v1alpha1"
	nipoolv1alpha1 "github.com/yndd/nddr-ni-pool/apis/nipool/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	NiPrefix      = "infra"
	NiAllocPrefix = "alloc-ni"

	errCreateNetworkInstance   = "cannot create NetworkInstance"
	errDeleteNetworkInstance   = "cannot delete NetworkInstance"
	errGetNetworkInstance      = "cannot get NetworkInstance"
	errUnavailableNiAllocation = "networkInstance alocation not available"
)

type NiKind string

const (
	NiKindRouted  NiKind = "routed"
	NiKindBridged NiKind = "bridged"
)

func (s NiKind) String() string {
	switch s {
	case NiKindRouted:
		return "routed"
	case NiKindBridged:
		return "bridged"
	}
	return "routed"
}

// InfraOption is used to configure the Infra.
type NiOption func(*ni)

func WithNiLogger(log logging.Logger) NiOption {
	return func(r *ni) {
		r.log = log
	}
}

func WithNiK8sClient(c resource.ClientApplicator) NiOption {
	return func(r *ni) {
		r.client = c
	}
}

func WithNiIpamClient(c resourcepb.ResourceClient) NiOption {
	return func(r *ni) {
		r.ipamClient = c
	}
}

func WithNiAsPoolClient(c resourcepb.ResourceClient) NiOption {
	return func(r *ni) {
		r.aspoolClient = c
	}
}

func NewNi(n Node, name string, opts ...NiOption) Ni {
	i := &ni{
		node:      n,
		name:      &name,
		subitfces: make(map[string]SubInterface),
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ Ni = &ni{}

type Ni interface {
	GetNode() Node
	GetName() string
	GetKind() string
	GetSubInterfaces() map[string]SubInterface

	SetKind(NiKind)

	GetNiRegister(ctx context.Context, cr infrav1alpha1.If, n string) (*string, error)
	CreateNiRegister(ctx context.Context, cr infrav1alpha1.If, n string) error
	DeleteNiRegister(ctx context.Context, cr infrav1alpha1.If, n string) error

	GetNddaNiInterfaces() []*networkv1alpha1.NetworkNetworkInstanceInterface
	GetNddaNi(ctx context.Context, cr infrav1alpha1.If) (*string, error)
	CreateNddaNi(ctx context.Context, cr infrav1alpha1.If) error
	DeleteNddaNi(ctx context.Context, cr infrav1alpha1.If) error

	Print(string, int)
}

type ni struct {
	client       resource.ClientApplicator
	ipamClient   resourcepb.ResourceClient
	aspoolClient resourcepb.ResourceClient
	//client client.Client
	log logging.Logger

	node Node
	name *string
	kind NiKind
	//as        *uint32
	subitfces map[string]SubInterface
}

func (x *ni) GetNode() Node {
	return x.node
}

func (x *ni) GetName() string {
	if reflect.ValueOf(x.name).IsZero() {
		return ""
	}
	return *x.name
}

func (x *ni) GetKind() string {
	return x.kind.String()
}

func (x *ni) GetSubInterfaces() map[string]SubInterface {
	return x.subitfces
}

func (x *ni) SetKind(s NiKind) {
	x.kind = s
}

func (x *ni) GetNiRegister(ctx context.Context, cr infrav1alpha1.If, n string) (*string, error) {
	o := x.buildNiAlloc(cr, n)
	if err := x.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(), Name: o.GetName()}, o); err != nil {
		return nil, errors.Wrap(err, errGetNetworkInstance)
	}
	if o.GetCondition(aspoolv1alpha1.ConditionKindReady).Status == corev1.ConditionTrue {
		if ni, ok := o.HasNi(); ok {
			return &ni, nil
		}
		x.log.Debug("strange NI alloc ready but no NI allocated")
		return nil, errors.Errorf("%s: %s", errUnavailableNiAllocation, "strange NI alloc ready but no NI allocated")
	}
	return nil, errors.Errorf("%s: %s", errUnavailableNiAllocation, o.GetCondition(aspoolv1alpha1.ConditionKindReady).Message)
}

func (x *ni) CreateNiRegister(ctx context.Context, cr infrav1alpha1.If, n string) error {
	o := x.buildNiAlloc(cr, n)
	if err := x.client.Apply(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteNetworkInstance)
	}
	return nil
}

func (x *ni) DeleteNiRegister(ctx context.Context, cr infrav1alpha1.If, n string) error {
	o := x.buildNiAlloc(cr, n)
	if err := x.client.Delete(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteNetworkInstance)
	}
	return nil
}

func (x *ni) buildNiAlloc(cr infrav1alpha1.If, n string) *nipoolv1alpha1.Alloc {
	return &nipoolv1alpha1.Alloc{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{NiAllocPrefix, cr.GetName(), n, x.GetNode().GetName()}, "-"),
			Namespace: cr.GetNamespace(),
			Labels: map[string]string{
				nipoolv1alpha1.LabelNiKey: n,
			},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: nipoolv1alpha1.AllocSpec{
			NiPoolName: utils.StringPtr("test"), // TODO We need to build a global register
			Alloc: &nipoolv1alpha1.NipoolAlloc{
				Selector: []*nipoolv1alpha1.NipoolAllocSelectorTag{
					{Key: utils.StringPtr(nipoolv1alpha1.NiSelectorKey), Value: utils.StringPtr(n)},
				},
				SourceTag: []*nipoolv1alpha1.NipoolAllocSourceTagTag{},
			},
		},
	}
}

func (x *ni) Print(niName string, n int) {
	fmt.Printf("%s Ni Name: %s Kind: %s\n", strings.Repeat(" ", n), niName, x.GetKind())
	n++
	for subitfceName, i := range x.subitfces {
		i.Print(subitfceName, n)
	}

}

func (x *ni) GetNddaNi(ctx context.Context, cr infrav1alpha1.If) (*string, error) {
	o := x.buildNddaNi(cr)
	if err := x.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(), Name: o.GetName()}, o); err != nil {
		return nil, errors.Wrap(err, errGetNetworkInstance)
	}
	return utils.StringPtr(o.GetName()), nil
}

func (x *ni) CreateNddaNi(ctx context.Context, cr infrav1alpha1.If) error {
	o := x.buildNddaNi(cr)
	if err := x.client.Apply(ctx, o); err != nil {
		return errors.Wrap(err, errGetNetworkInstance)
	}
	return nil
}

func (x *ni) DeleteNddaNi(ctx context.Context, cr infrav1alpha1.If) error {
	o := x.buildNddaNi(cr)
	if err := x.client.Delete(ctx, o); err != nil {
		return errors.Wrap(err, errDeleteNetworkInstance)
	}
	return nil
}

func (x *ni) GetNddaNiInterfaces() []*networkv1alpha1.NetworkNetworkInstanceInterface {
	sis := make([]*networkv1alpha1.NetworkNetworkInstanceInterface, 0, len(x.subitfces))
	for _, si := range x.subitfces {
		sis = append(sis, &networkv1alpha1.NetworkNetworkInstanceInterface{
			Name: utils.StringPtr(strings.Join([]string{si.GetInterface().GetName(), si.GetIndex()}, ".")),
			Kind: utils.StringPtr(si.GetInterface().GetKind()),
		})
	}
	return sis
}

func (x *ni) buildNddaNi(cr infrav1alpha1.If) *networkv1alpha1.NetworkInstance {
	orgName := cr.GetOrganizationName()
	depName := cr.GetDeploymentName()

	objMeta := metav1.ObjectMeta{
		Name:      strings.Join([]string{orgName, depName, x.GetName(), x.GetKind(), x.GetNode().GetName()}, "."),
		Namespace: cr.GetNamespace(),
		Labels: map[string]string{
			networkv1alpha1.LabelNetworkInstanceKindKey: x.GetKind(),
		},
		OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
	}

	switch x.GetKind() {
	case NiKindBridged.String():

		return &networkv1alpha1.NetworkInstance{
			ObjectMeta: objMeta,
			Spec: networkv1alpha1.NetworkInstanceSpec{
				NodeName: utils.StringPtr(x.GetNode().GetName()),
				//EndpointGroup: utils.StringPtr(cr.GetName()),
				NetworkInstance: &networkv1alpha1.NetworkNetworkInstance{
					Name:      utils.StringPtr(x.GetName()),
					Kind:      utils.StringPtr(x.GetKind()),
					Interface: x.GetNddaNiInterfaces(),
				},
			},
		}
	default:
		// routed
		return &networkv1alpha1.NetworkInstance{
			ObjectMeta: objMeta,
			Spec: networkv1alpha1.NetworkInstanceSpec{
				NodeName: utils.StringPtr(x.GetNode().GetName()),
				//EndpointGroup: utils.StringPtr(cr.GetName()),
				NetworkInstance: &networkv1alpha1.NetworkNetworkInstance{
					Name:      utils.StringPtr(x.GetName()),
					Kind:      utils.StringPtr(x.GetKind()),
					Interface: x.GetNddaNiInterfaces(),
				},
			},
		}
	}
}
