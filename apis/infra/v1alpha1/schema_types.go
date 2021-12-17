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

// Nddoinfrastructure struct
type Nddoinfrastructure struct {
	Infrastructure []*NddoinfrastructureInfrastructure `json:"infrastructure,omitempty"`
}

// NddoinfrastructureInfrastructure struct
type NddoinfrastructureInfrastructure struct {
	AddressingScheme *string `json:"addressing-scheme,omitempty"`
	AdminState       *string `json:"admin-state,omitempty"`
	Description      *string `json:"description,omitempty"`
	InterfaceTagPool *string `json:"interface-tag-pool,omitempty"`
	IslIpamPool      *string `json:"isl-ipam-pool,omitempty"`
	LoopbackIpamPool *string `json:"loopback-ipam-pool,omitempty"`
	OverlayAsPool    *string `json:"overlay-as-pool,omitempty"`
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=16
	OverlayProtocol []*string                              `json:"overlay-protocol,omitempty"`
	State           *NddoinfrastructureInfrastructureState `json:"state,omitempty"`
	TopologyName    *string                                `json:"topology-name,omitempty"`
	UnderlayAsPool  *string                                `json:"underlay-as-pool,omitempty"`
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=16
	UnderlayProtocol []*string `json:"underlay-protocol,omitempty"`
}

// NddoinfrastructureInfrastructureState struct
type NddoinfrastructureInfrastructureState struct {
	LastUpdate *string                                      `json:"last-update,omitempty"`
	Node       []*NddoinfrastructureInfrastructureStateNode `json:"node,omitempty"`
	Link       []*NddoinfrastructureInfrastructureStateLink `json:"link,omitempty"`
	Reason     *string                                      `json:"reason,omitempty"`
	Status     *string                                      `json:"status,omitempty"`
}

// NddoinfrastructureInfrastructureStateNode struct
type NddoinfrastructureInfrastructureStateNode struct {
	Endpoint []*NddoinfrastructureInfrastructureStateNodeEndpoint `json:"endpoint,omitempty"`
	Name     *string                                              `json:"name"`
}

// NddoinfrastructureInfrastructureStateNodeEndpoint struct
type NddoinfrastructureInfrastructureStateNodeEndpoint struct {
	Lag        *bool   `json:"lag,omitempty"`
	LagSubLink *bool   `json:"lag-sub-link,omitempty"`
	Name       *string `json:"name"`
}

// NddoinfrastructureInfrastructureStateLink struct
type NddoinfrastructureInfrastructureStateLink struct {
}

// Root is the root of the schema
type Root struct {
	InfraNddoinfrastructure *Nddoinfrastructure `json:"nddo-infrastructure,omitempty"`
}
