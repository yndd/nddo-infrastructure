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
	ipamv1alpha1 "github.com/yndd/nddr-ipam/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
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

func WithLinkClient(c resource.ClientApplicator) LinkOption {
	return func(r *link) {
		r.client = c
	}
}

func NewLink(n string, opts ...LinkOption) Link {
	i := &link{
		name: &n,
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ Link = &link{}

type Link interface {
	GetName() string
	AllocateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl) error
	DeAllocateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl) error
	ValidateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl) (*string, error)
}

type link struct {
	client resource.ClientApplicator
	log    logging.Logger

	name *string
}

func (x *link) GetName() string {
	return *x.name
}

func (x *link) AllocateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl) error {
	ipamAlloc := buildIpamAllocLink(cr, tl)
	if err := x.client.Apply(ctx, ipamAlloc); err != nil {
		return errors.Wrap(err, errApplyAllocIpam)
	}
	return nil
}

func (x *link) DeAllocateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl) error {
	ipamAlloc := buildIpamAllocLink(cr, tl)
	if err := x.client.Delete(ctx, ipamAlloc); err != nil {
		return errors.Wrap(err, errDeleteAllocIpam)
	}
	return nil
}

func (x *link) ValidateLinkIP(ctx context.Context, cr infrav1alpha1.If, tl topov1alpha1.Tl) (*string, error) {
	ipamAlloc := buildIpamAllocLink(cr, tl)
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
