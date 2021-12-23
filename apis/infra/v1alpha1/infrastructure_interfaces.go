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

package v1alpha1

import (
	"reflect"

	nddv1 "github.com/yndd/ndd-runtime/apis/common/v1"
	"github.com/yndd/ndd-runtime/pkg/resource"
	"github.com/yndd/ndd-runtime/pkg/utils"
)

var _ If = &Infrastructure{}

// +k8s:deepcopy-gen=false
type If interface {
	resource.Object
	resource.Conditioned

	GetControllerReference() nddv1.Reference
	SetControllerReference(c nddv1.Reference)

	GetAdminState() string
	GetDescription() string
	GetTopologyName() string
	GetAddressingScheme() string
	GetInterfaceTagPool() string
	GetIslIpamPool() string
	GetLoopbackIpamPool() string
	GetOverlayAsPool() string
	GetUnderlayAsPool() string
	GetUnderlayProtocol() []string
	GetOverlayProtocol() []string
	InitializeResource() error

	SetStatus(string)
	SetReason(string)
	GetStatus() string
}

// GetCondition of this Network Node.
func (x *Infrastructure) GetCondition(ct nddv1.ConditionKind) nddv1.Condition {
	return x.Status.GetCondition(ct)
}

// SetConditions of the Network Node.
func (x *Infrastructure) SetConditions(c ...nddv1.Condition) {
	x.Status.SetConditions(c...)
}

// GetControllerReference of the Network Node.
func (x *Infrastructure) GetControllerReference() nddv1.Reference {
	return x.Status.ControllerRef
}

// SetControllerReference of the Network Node.
func (x *Infrastructure) SetControllerReference(c nddv1.Reference) {
	x.Status.ControllerRef = c
}

func (x *Infrastructure) GetAdminState() string {
	if reflect.ValueOf(x.Spec.Infrastructure.AdminState).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.AdminState
}

func (x *Infrastructure) GetDescription() string {
	if reflect.ValueOf(x.Spec.Infrastructure.Description).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.Description
}

func (x *Infrastructure) GetTopologyName() string {
	if reflect.ValueOf(x.Spec.Infrastructure.TopologyName).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.TopologyName
}

func (x *Infrastructure) GetAddressingScheme() string {
	if reflect.ValueOf(x.Spec.Infrastructure.AddressingScheme).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.AddressingScheme
}

func (x *Infrastructure) GetInterfaceTagPool() string {
	if reflect.ValueOf(x.Spec.Infrastructure.InterfaceTagPool).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.InterfaceTagPool
}

func (x *Infrastructure) GetIslIpamPool() string {
	if reflect.ValueOf(x.Spec.Infrastructure.IslIpamPool).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.IslIpamPool
}

func (x *Infrastructure) GetLoopbackIpamPool() string {
	if reflect.ValueOf(x.Spec.Infrastructure.LoopbackIpamPool).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.LoopbackIpamPool
}

func (x *Infrastructure) GetOverlayAsPool() string {
	if reflect.ValueOf(x.Spec.Infrastructure.OverlayAsPool).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.OverlayAsPool
}

func (x *Infrastructure) GetUnderlayAsPool() string {
	if reflect.ValueOf(x.Spec.Infrastructure.UnderlayAsPool).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.UnderlayAsPool
}

func (x *Infrastructure) GetOverlayProtocol() []string {
	s := make([]string, 0)
	if reflect.ValueOf(x.Spec.Infrastructure.OverlayProtocol).IsZero() {
		return s
	}
	for _, protocol := range x.Spec.Infrastructure.OverlayProtocol {
		s = append(s, *protocol)
	}
	return s
}

func (x *Infrastructure) GetUnderlayProtocol() []string {
	s := make([]string, 0)
	if reflect.ValueOf(x.Spec.Infrastructure.UnderlayProtocol).IsZero() {
		return s
	}
	for _, protocol := range x.Spec.Infrastructure.UnderlayProtocol {
		s = append(s, *protocol)
	}
	return s
}

func (x *Infrastructure) InitializeResource() error {
	if x.Status.Infrastructure != nil {
		// pool was already initialiazed
		// copy the spec, but not the state
		x.Status.Infrastructure.AdminState = x.Spec.Infrastructure.AdminState
		x.Status.Infrastructure.Description = x.Spec.Infrastructure.Description
		x.Status.Infrastructure.AddressingScheme = x.Spec.Infrastructure.AddressingScheme
		x.Status.Infrastructure.InterfaceTagPool = x.Spec.Infrastructure.InterfaceTagPool
		x.Status.Infrastructure.IslIpamPool = x.Spec.Infrastructure.IslIpamPool
		x.Status.Infrastructure.LoopbackIpamPool = x.Spec.Infrastructure.LoopbackIpamPool
		x.Status.Infrastructure.OverlayAsPool = x.Spec.Infrastructure.OverlayAsPool
		x.Status.Infrastructure.OverlayProtocol = x.Spec.Infrastructure.OverlayProtocol
		x.Status.Infrastructure.TopologyName = x.Spec.Infrastructure.TopologyName
		x.Status.Infrastructure.UnderlayAsPool = x.Spec.Infrastructure.UnderlayAsPool
		x.Status.Infrastructure.UnderlayProtocol = x.Spec.Infrastructure.UnderlayProtocol
		return nil
	}

	x.Status.Infrastructure = &NddoinfrastructureInfrastructure{
		AdminState:       x.Spec.Infrastructure.AdminState,
		Description:      x.Spec.Infrastructure.Description,
		AddressingScheme: x.Spec.Infrastructure.AddressingScheme,
		InterfaceTagPool: x.Spec.Infrastructure.InterfaceTagPool,
		IslIpamPool:      x.Spec.Infrastructure.IslIpamPool,
		LoopbackIpamPool: x.Spec.Infrastructure.LoopbackIpamPool,
		OverlayAsPool:    x.Spec.Infrastructure.OverlayAsPool,
		OverlayProtocol:  x.Spec.Infrastructure.OverlayProtocol,
		TopologyName:     x.Spec.Infrastructure.TopologyName,
		UnderlayAsPool:   x.Spec.Infrastructure.UnderlayAsPool,
		UnderlayProtocol: x.Spec.Infrastructure.UnderlayProtocol,
		State: &NddoinfrastructureInfrastructureState{
			Status: utils.StringPtr(""),
			Reason: utils.StringPtr(""),
			Node:   make([]*NddoinfrastructureInfrastructureStateNode, 0),
			Link:   make([]*NddoinfrastructureInfrastructureStateLink, 0),
		},
	}
	return nil
}

func (x *Infrastructure) SetStatus(s string) {
	x.Status.Infrastructure.State.Status = &s
}

func (x *Infrastructure) SetReason(s string) {
	x.Status.Infrastructure.State.Reason = &s
}

func (x *Infrastructure) GetStatus() string {
	if x.Status.Infrastructure != nil && x.Status.Infrastructure.State != nil && x.Status.Infrastructure.State.Status != nil {
		return *x.Status.Infrastructure.State.Status
	}
	return "unknown"
}

type AddressingScheme string

const (
	AddressingSchemeDualStack AddressingScheme = "dual-stack"
	AddressingSchemeIpv4Only  AddressingScheme = "ipv4-only"
	AddressingSchemeIpv6Only  AddressingScheme = "ipv6-only"
)

func (s AddressingScheme) String() string {
	switch s {
	case AddressingSchemeDualStack:
		return "dual-stack"
	case AddressingSchemeIpv4Only:
		return "ipv4-only"
	case AddressingSchemeIpv6Only:
		return "ipv6-only"
	}
	return "unknown"
}

type Protocol string

const (
	ProtocolEBGP        Protocol = "ebgp"
	ProtocolIBGP        Protocol = "ibgp"
	ProtocolISIS        Protocol = "isis"
	ProtocolOSPF        Protocol = "ospf"
	ProtocolEVPN        Protocol = "evpn"
	ProtocolIPVPN       Protocol = "ipvpn"
	ProtocolRouteTarget Protocol = "route-target"
)

func (s Protocol) String() string {
	switch s {
	case ProtocolEBGP:
		return "ebgp"
	case ProtocolIBGP:
		return "ibgp"
	case ProtocolISIS:
		return "isis"
	case ProtocolOSPF:
		return "ospf"
	case ProtocolEVPN:
		return "evpn"
	case ProtocolIPVPN:
		return "ipvpn"
	case ProtocolRouteTarget:
		return "route-target"
	}
	return "unknown"
}
