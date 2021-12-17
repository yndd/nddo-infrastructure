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

	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/resource"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	aspoolv1alpha1 "github.com/yndd/nddr-as-pool/apis/aspool/v1alpha1"
	ipamv1alpha1 "github.com/yndd/nddr-ipam/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// InfraOption is used to configure the Infra.
type NodeOption func(*node)

func WithNodeLogger(log logging.Logger) NodeOption {
	return func(r *node) {
		r.log = log
	}
}

func WithNodeClient(c resource.ClientApplicator) NodeOption {
	return func(r *node) {
		r.client = c
	}
}

func NewNode(opts ...NodeOption) Node {
	i := &node{
		itfces: make([]Interface, 0),
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ Node = &node{}

type Node interface {
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
	GetInterfaces() []Interface
	GetInterface(string) Interface
	AddInterface(Interface)
	DeleteInterface(Interface)
	AllocateAS(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tn) error
	DeAllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) error
	ValidateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) (*uint32, error)
	AllocateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) error
	DeAllocateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) error
	ValidateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) (*string, error)
}

type node struct {
	client resource.ClientApplicator
	log    logging.Logger

	name     *string
	index    *uint32
	kind     NodeKind
	platform *string
	as       *uint32
	itfces   []Interface
}

func (x *node) GetName() string {
	return *x.name
}

func (x *node) GetIndex() uint32 {
	return *x.index
}

func (x *node) GetKind() string {
	return x.kind.String()
}

func (x *node) GetPlatform() string {
	return *x.platform
}

func (x *node) GetAS() uint32 {
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

func (x *node) GetInterfaces() []Interface {
	return x.itfces
}

func (x *node) GetInterface(n string) Interface {
	for _, i := range x.itfces {
		if i.GetName() == n {
			return i
		}
	}
	return nil
}

func (x *node) AddInterface(n Interface) {
	for _, i := range x.itfces {
		if i.GetName() == n.GetName() {
			i = n
			return
		}
	}
	x.itfces = append(x.itfces, n)
}

func (x *node) DeleteInterface(n Interface) {
	found := false
	idx := 0
	for i, itfce := range x.itfces {
		if itfce.GetName() == n.GetName() {
			idx = i
			found = true
		}
	}
	if found {
		x.itfces = append(append(x.itfces[:idx], x.itfces[idx+1:]...))
	}
}

func (x *node) AllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) error {
	aspoolAlloc := buildAsPoolAllocByIndex(cr, tn)
	if err := x.client.Apply(ctx, aspoolAlloc); err != nil {
		return errors.Wrap(err, errApplyAllocAS)
	}
	return nil
}

func (x *node) DeAllocateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) error {
	aspoolAlloc := buildAsPoolAllocByIndex(cr, tn)
	if err := x.client.Delete(ctx, aspoolAlloc); err != nil {
		return errors.Wrap(err, errDeleteAllocAS)
	}
	return nil
}

func (x *node) ValidateAS(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) (*uint32, error) {
	aspoolAlloc := buildAsPoolAllocByIndex(cr, tn)
	if err := x.client.Get(ctx, types.NamespacedName{Namespace: cr.GetNamespace(), Name: aspoolAlloc.GetName()}, aspoolAlloc); err != nil {
		return nil, errors.Wrap(err, errGetAllocAS)
	}
	if aspoolAlloc.GetCondition(aspoolv1alpha1.ConditionKindAllocationReady).Status == corev1.ConditionTrue {
		if as, ok := aspoolAlloc.HasAs(); ok {
			return &as, nil
		}
		x.log.Debug("strange AS alloc ready but no Ip prefix allocated")
		return nil, errors.Errorf("%s: %s", errUnavailableIpamAllocation, "strange AS alloc ready but no Ip prefix allocated")
	}
	return nil, errors.Errorf("%s: %s", errUnavailableAsPoolAllocation, aspoolAlloc.GetCondition(aspoolv1alpha1.ConditionKindAllocationReady).Message)
}

func (x *node) AllocateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) error {
	ipamAlloc := buildIpamAllocLoopback(cr, tn)
	if err := x.client.Apply(ctx, ipamAlloc); err != nil {
		return errors.Wrap(err, errApplyAllocIpam)
	}
	return nil
}

func (x *node) DeAllocateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) error {
	ipamAlloc := buildIpamAllocLoopback(cr, tn)
	if err := x.client.Delete(ctx, ipamAlloc); err != nil {
		return errors.Wrap(err, errDeleteAllocIpam)
	}
	return nil
}

func (x *node) ValidateLoopbackIP(ctx context.Context, cr infrav1alpha1.If, tn topov1alpha1.Tn) (*string, error) {
	ipamAlloc := buildIpamAllocLoopback(cr, tn)
	if err := x.client.Get(ctx, types.NamespacedName{Namespace: cr.GetNamespace(), Name: ipamAlloc.GetName()}, ipamAlloc); err != nil {
		return nil, errors.Wrap(err, errGetAllocIpam)
	}
	if ipamAlloc.GetCondition(ipamv1alpha1.ConditionKindAllocationReady).Status == corev1.ConditionTrue {
		if prefix, ok := ipamAlloc.HasIpPrefix(); ok {
			return &prefix, nil
		}
		x.log.Debug("strange ipam alloc ready but no Ip prefix allocated")
		return nil, errors.Errorf("%s: %s", errUnavailableIpamAllocation, "strange ipam alloc ready but no Ip prefix allocated")
	}
	return nil, errors.Errorf("%s: %s", errUnavailableIpamAllocation, ipamAlloc.GetCondition(ipamv1alpha1.ConditionKindAllocationReady).Message)
}

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
