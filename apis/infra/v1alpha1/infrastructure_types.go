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
	nddov1 "github.com/yndd/nddo-runtime/apis/common/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Infrastructure struct
type InfraInfrastructure struct {
	// +kubebuilder:validation:Enum=`dual-stack`;`ipv4-only`;`ipv6-only`
	AddressingScheme *string `json:"addressing-scheme,omitempty"`
	// +kubebuilder:validation:Enum=`disable`;`enable`
	// +kubebuilder:default:="enable"
	AdminState *string `json:"admin-state,omitempty"`
	// kubebuilder:validation:MinLength=1
	// kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern="[A-Za-z0-9 !@#$^&()|+=`~.,'/_:;?-]*"
	Description *string `json:"description,omitempty"`
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=16
	OverlayProtocol []*string `json:"overlay-protocol,omitempty"`
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=16
	UnderlayProtocol  []*string                   `json:"underlay-protocol,omitempty"`
	InterfaceSelector []*nddov1.InterfaceSelector `json:"interface-selector,omitempty"`
}

// A InfrastructureSpec defines the desired state of a Infrastructure.
type InfrastructureSpec struct {
	//nddv1.ResourceSpec `json:",inline"`
	Infrastructure *InfraInfrastructure `json:"infrastructure,omitempty"`
}

// A InfrastructureStatus represents the observed state of a InfrastructureSpec.
type InfrastructureStatus struct {
	nddv1.ConditionedStatus `json:",inline"`
	OrganizationName        *string                           `json:"organization-name,omitempty"`
	DeploymentName          *string                           `json:"deployment-name,omitempty"`
	NetworkInstanceName     *string                           `json:"network-instance-name,omitempty"`
	Infrastructure          *NddoinfrastructureInfrastructure `json:"infrastructure,omitempty"`
}

// +kubebuilder:object:root=true

// InfraInfrastructure is the Schema for the Infrastructure API
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="SYNC",type="string",JSONPath=".status.conditions[?(@.kind=='Synced')].status"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.conditions[?(@.kind=='Ready')].status"
// +kubebuilder:printcolumn:name="ORG",type="string",JSONPath=".status.organization-name"
// +kubebuilder:printcolumn:name="DEPL",type="string",JSONPath=".status.deployment-name"
// +kubebuilder:printcolumn:name="NI",type="string",JSONPath=".status.network-instance-name"
// +kubebuilder:printcolumn:name="ADDR",type="string",JSONPath=".spec.infrastructure.addressing-scheme"
// +kubebuilder:printcolumn:name="UNDERLAY",type="string",JSONPath=".spec.infrastructure.underlay-protocol[0]"
// +kubebuilder:printcolumn:name="OVERLAY",type="string",JSONPath=".spec.infrastructure.overlay-protocol[0]"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type Infrastructure struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   InfrastructureSpec   `json:"spec,omitempty"`
	Status InfrastructureStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// InfrastructureList contains a list of Infrastructures
type InfrastructureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Infrastructure `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Infrastructure{}, &InfrastructureList{})
}

// Infrastructure type metadata.
var (
	InfrastructureKindKind         = reflect.TypeOf(Infrastructure{}).Name()
	InfrastructureGroupKind        = schema.GroupKind{Group: Group, Kind: InfrastructureKindKind}.String()
	InfrastructureKindAPIVersion   = InfrastructureKindKind + "." + GroupVersion.String()
	InfrastructureGroupVersionKind = GroupVersion.WithKind(InfrastructureKindKind)
)
