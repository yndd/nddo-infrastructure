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
	nddov1 "github.com/yndd/nddo-runtime/apis/common/v1"
	"github.com/yndd/nddo-runtime/pkg/odns"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ IfList = &InfrastructureList{}

// +k8s:deepcopy-gen=false
type IfList interface {
	client.ObjectList

	GetInfrastructures() []If
}

func (x *InfrastructureList) GetInfrastructures() []If {
	xs := make([]If, len(x.Items))
	for i, r := range x.Items {
		r := r // Pin range variable so we can take its address.
		xs[i] = &r
	}
	return xs
}

var _ If = &Infrastructure{}

// +k8s:deepcopy-gen=false
type If interface {
	resource.Object
	resource.Conditioned

	GetCondition(ct nddv1.ConditionKind) nddv1.Condition
	SetConditions(c ...nddv1.Condition)
	GetDeploymentPolicy() nddov1.DeploymentPolicy
	SetDeploymentPolicy(nddov1.DeploymentPolicy)
	GetOrganization() string
	GetDeployment() string
	GetAvailabilityZone() string
	GetInfraName() string
	GetNetworkInstanceName() string
	GetAdminState() string
	GetDescription() string
	GetAddressingScheme() string
	GetUnderlayProtocol() []string
	GetOverlayProtocol() []string
	GetCidr() *InfraInfrastructureCidr
	GetIslCidrIpv4() string
	GetIslCidrIpv6() string
	GetLoopbackCidrIpv4() string
	GetLoopbackCidrIpv6() string
	GetAsPool() *InfraInfrastructureASPool
	GetAsPoolStart() uint32
	GetAsPoolEnd() uint32
	InitializeResource() error

	SetStatus(string)
	SetReason(string)
	GetStatus() string
	SetOrganization(string)
	SetDeployment(string)
	SetAvailabilityZone(s string)
	SetNetworkInstanceName(s string)
}

// GetCondition of this Network Node.
func (x *Infrastructure) GetCondition(ct nddv1.ConditionKind) nddv1.Condition {
	return x.Status.GetCondition(ct)
}

// SetConditions of the Network Node.
func (x *Infrastructure) SetConditions(c ...nddv1.Condition) {
	x.Status.SetConditions(c...)
}

func (x *Infrastructure) GetDeploymentPolicy() nddov1.DeploymentPolicy {
	return x.Spec.DeploymentPolicy
}

func (x *Infrastructure) SetDeploymentPolicy(c nddov1.DeploymentPolicy) {
	x.Spec.DeploymentPolicy = c
}

func (x *Infrastructure) GetOrganization() string {
	return odns.Name2OdnsResource(x.GetName()).GetOrganization()
}

func (x *Infrastructure) GetDeployment() string {
	return odns.Name2OdnsResource(x.GetName()).GetDeployment()
}

func (x *Infrastructure) GetAvailabilityZone() string {
	return odns.Name2OdnsResource(x.GetName()).GetAvailabilityZone()
}

func (x *Infrastructure) GetInfraName() string {
	return odns.Name2OdnsResource(x.GetName()).GetResourceName()
}

func (x *Infrastructure) GetNetworkInstanceName() string {
	if reflect.ValueOf(x.Spec.Infrastructure.NetworkInstanceName).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.NetworkInstanceName
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

func (x *Infrastructure) GetAddressingScheme() string {
	if reflect.ValueOf(x.Spec.Infrastructure.AddressingScheme).IsZero() {
		return ""
	}
	return *x.Spec.Infrastructure.AddressingScheme
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

func (x *Infrastructure) GetCidr() *InfraInfrastructureCidr {
	return x.Spec.Infrastructure.Cidr

}

func (x *Infrastructure) GetAS() uint32 {
	return *x.Spec.Infrastructure.AS
}

func (x *Infrastructure) GetIslCidrIpv4() string {
	return *x.Spec.Infrastructure.Cidr.IslCidrIpv4
}

func (x *Infrastructure) GetIslCidrIpv6() string {
	return *x.Spec.Infrastructure.Cidr.IslCidrIpv6
}

func (x *Infrastructure) GetLoopbackCidrIpv4() string {
	return *x.Spec.Infrastructure.Cidr.LoopbackCidrIpv4
}

func (x *Infrastructure) GetLoopbackCidrIpv6() string {
	return *x.Spec.Infrastructure.Cidr.LoopbackCidrIpv6
}

func (x *Infrastructure) GetAsPool() *InfraInfrastructureASPool {
	return x.Spec.Infrastructure.ASpool
}

func (x *Infrastructure) GetAsPoolStart() uint32 {
	return *x.Spec.Infrastructure.ASpool.Start
}

func (x *Infrastructure) GetAsPoolEnd() uint32 {
	return *x.Spec.Infrastructure.ASpool.End
}

func (x *Infrastructure) InitializeResource() error {
	if x.Status.Infrastructure != nil {
		// pool was already initialiazed
		// copy the spec, but not the state
		x.Status.Infrastructure.AdminState = x.Spec.Infrastructure.AdminState
		x.Status.Infrastructure.Description = x.Spec.Infrastructure.Description
		x.Status.Infrastructure.AddressingScheme = x.Spec.Infrastructure.AddressingScheme
		x.Status.Infrastructure.OverlayProtocol = x.Spec.Infrastructure.OverlayProtocol
		x.Status.Infrastructure.UnderlayProtocol = x.Spec.Infrastructure.UnderlayProtocol
		return nil
	}

	x.Status.Infrastructure = &NddoinfrastructureInfrastructure{
		AdminState:       x.Spec.Infrastructure.AdminState,
		Description:      x.Spec.Infrastructure.Description,
		AddressingScheme: x.Spec.Infrastructure.AddressingScheme,
		OverlayProtocol:  x.Spec.Infrastructure.OverlayProtocol,
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

func (x *Infrastructure) SetOrganization(s string) {
	x.Status.SetOrganization(s)
}

func (x *Infrastructure) SetDeployment(s string) {
	x.Status.SetDeployment(s)
}

func (x *Infrastructure) SetAvailabilityZone(s string) {
	x.Status.SetAvailabilityZone(s)
}

func (x *Infrastructure) SetNetworkInstanceName(s string) {
	x.Status.NetworkInstanceName = &s
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
