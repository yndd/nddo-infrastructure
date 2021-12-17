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
	"time"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"

	//nddv1 "github.com/yndd/ndd-runtime/apis/common/v1"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/resource"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"

	aspoolv1alpha1 "github.com/yndd/nddr-as-pool/apis/aspool/v1alpha1"
	ipamv1alpha1 "github.com/yndd/nddr-ipam/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

const (
	errApplyAsPoolAlloc = "cannot apply AS pool allocation"
	errApplyIpamAlloc   = "cannot apply ipam allocation"
	errGetAsPoolAlloc   = "cannot get AS pool allocation"
	errGetIpamAlloc     = "cannot get ipam allocation"

	errUnavailableASPoolAllocation = "aspool allocation is unavailable"
	errUnavailableIpamAllocation   = "ipam allocation is unavailable"
)

// A Hooks performs operations to desploy/destroy .
type NodeHooks interface {
	// Deploy performs operations to deploy the child resources
	Deploy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tn) error

	// Validate performs operations to validate the allocations of the child resources
	Validate(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tn) error

	// Destroy performs operations to deploy the child resources
	Destroy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tn) error
}

// DeviceDriverHooks performs operations to deploy the device driver.
type NodeHook struct {
	client resource.ClientApplicator
	log    logging.Logger
}

func NewNodeHook(client resource.ClientApplicator, log logging.Logger) NodeHooks {
	return &NodeHook{
		client: client,
		log:    log,
	}
}

func (h *NodeHook) Deploy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tn) error {
	aspoolAlloc := buildAsPoolAllocByIndex(cr, x)
	if err := h.client.Apply(ctx, aspoolAlloc); err != nil {
		return errors.Wrap(err, errApplyAsPoolAlloc)
	}

	ipamAlloc := buildIpamAllocLoopback(cr, x)
	if err := h.client.Apply(ctx, ipamAlloc); err != nil {
		return errors.Wrap(err, errApplyIpamAlloc)
	}

	//cr.SetControllerReference(nddv1.Reference{Name: cr.GetName()})

	//time.Sleep(1 * time.Second)

	/*
		if err := h.client.Get(ctx, types.NamespacedName{Namespace: cr.GetNamespace(), Name: aspoolAlloc.GetName()}, aspoolAlloc); err != nil {
			return err
		}
		h.log.Debug("Deploy aspool alloc", "status", aspoolAlloc.GetCondition(aspoolv1alpha1.ConditionKindAllocationReady).Status)
		if aspoolAlloc.GetCondition(aspoolv1alpha1.ConditionKindAllocationReady).Status != corev1.ConditionTrue {
			return errors.Errorf("%s: %s", errUnavailableASPoolAllocation, aspoolAlloc.GetCondition(aspoolv1alpha1.ConditionKindAllocationReady).Message)
		}

		if err := h.client.Get(ctx, types.NamespacedName{Namespace: cr.GetNamespace(), Name: ipamAlloc.GetName()}, ipamAlloc); err != nil {
			return err
		}
		h.log.Debug("Deploy ipamAlloc alloc", "status", ipamAlloc.GetCondition(ipamv1alpha1.ConditionKindAllocationReady).Status)
		if ipamAlloc.GetCondition(ipamv1alpha1.ConditionKindAllocationReady).Status != corev1.ConditionTrue {
			return errors.Errorf("%s: %s", errUnavailableIpamAllocation, ipamAlloc.GetCondition(ipamv1alpha1.ConditionKindAllocationReady).Message)
		}
	*/

	return nil
}

func (h *NodeHook) Validate(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tn) error {
	time.Sleep(2 * time.Second)

	aspoolAlloc := buildAsPoolAllocByIndex(cr, x)
	if err := h.client.Get(ctx, types.NamespacedName{Namespace: cr.GetNamespace(), Name: aspoolAlloc.GetName()}, aspoolAlloc); err != nil {
		return errors.Wrap(err, errGetAsPoolAlloc)
	}
	h.log.Debug("Validate aspool alloc", "name", aspoolAlloc.GetName(), "status", aspoolAlloc.GetCondition(aspoolv1alpha1.ConditionKindAllocationReady).Status)
	if aspoolAlloc.GetCondition(aspoolv1alpha1.ConditionKindAllocationReady).Status != corev1.ConditionTrue {
		return errors.Errorf("%s: %s", errUnavailableASPoolAllocation, aspoolAlloc.GetCondition(aspoolv1alpha1.ConditionKindAllocationReady).Message)
	}
	if as, ok := aspoolAlloc.HasAs(); ok {
		h.log.Debug("AS Allocated", "Node", x.GetName(), "AS", as)
	} else {
		h.log.Debug("Strange aspool alloc ready but no AS allocated")
	}

	ipamAlloc := buildIpamAllocLoopback(cr, x)
	if err := h.client.Apply(ctx, ipamAlloc); err != nil {
		return errors.Wrap(err, errGetIpamAlloc)
	}
	h.log.Debug("Validate ipamAlloc alloc", "name", ipamAlloc.GetName(), "status", ipamAlloc.GetCondition(ipamv1alpha1.ConditionKindAllocationReady).Status)
	if ipamAlloc.GetCondition(ipamv1alpha1.ConditionKindAllocationReady).Status != corev1.ConditionTrue {
		return errors.Errorf("%s: %s", errUnavailableIpamAllocation, ipamAlloc.GetCondition(ipamv1alpha1.ConditionKindAllocationReady).Message)
	}

	if prefix, ok := ipamAlloc.HasIpPrefix(); ok {
		h.log.Debug("IP Prefix Allocated", "Node", x.GetName(), "AS", prefix)
	} else {
		h.log.Debug("Strange aspool alloc ready but no IP Prefix allocated")
	}

	return nil
}

func (h *NodeHook) Destroy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tn) error {
	aspoolAlloc := buildAsPoolAllocByIndex(cr, x)
	if err := h.client.Delete(ctx, aspoolAlloc); err != nil {
		return errors.Wrap(err, errApplyAsPoolAlloc)
	}

	ipamAlloc := buildIpamAllocLoopback(cr, x)
	if err := h.client.Delete(ctx, ipamAlloc); err != nil {
		return errors.Wrap(err, errApplyIpamAlloc)
	}
	//cr.SetControllerReference(nddv1.Reference{Name: cr.GetName()})

	return nil
}

// LinkHooks performs operations to desploy/destroy .
type LinkHooks interface {
	// Deploy performs operations to deploy the child resources
	Deploy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tl) error

	// Destroy performs operations to deploy the child resources
	Destroy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tl) error
}

// LinkHook performs operations to deploy the device driver.
type LinkHook struct {
	client resource.ClientApplicator
	log    logging.Logger
}

func NewLinkHook(client resource.ClientApplicator, log logging.Logger) LinkHooks {
	return &LinkHook{
		client: client,
		log:    log,
	}
}

func (h *LinkHook) Deploy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tl) error {
	return nil
}

func (h *LinkHook) Destroy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tl) error {
	return nil
}

// EpHooks performs operations to desploy/destroy .
type EpHooks interface {
	// Deploy performs operations to deploy the child resources
	Deploy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tl) error

	// Destroy performs operations to deploy the child resources
	Destroy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tl) error
}

// EpHook performs operations to deploy the device driver.
type EpHook struct {
	client resource.ClientApplicator
	log    logging.Logger
}

func NewEpHook(client resource.ClientApplicator, log logging.Logger) EpHooks {
	return &EpHook{
		client: client,
		log:    log,
	}
}

func (h *EpHook) Deploy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tl) error {
	return nil
}

func (h *EpHook) Destroy(ctx context.Context, cr infrav1alpha1.If, x topov1alpha1.Tl) error {
	return nil
}
