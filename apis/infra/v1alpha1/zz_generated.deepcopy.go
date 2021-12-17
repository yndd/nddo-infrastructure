//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InfraInfrastructure) DeepCopyInto(out *InfraInfrastructure) {
	*out = *in
	if in.AddressingScheme != nil {
		in, out := &in.AddressingScheme, &out.AddressingScheme
		*out = new(string)
		**out = **in
	}
	if in.AdminState != nil {
		in, out := &in.AdminState, &out.AdminState
		*out = new(string)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.InterfaceTagPool != nil {
		in, out := &in.InterfaceTagPool, &out.InterfaceTagPool
		*out = new(string)
		**out = **in
	}
	if in.IslIpamPool != nil {
		in, out := &in.IslIpamPool, &out.IslIpamPool
		*out = new(string)
		**out = **in
	}
	if in.LoopbackIpamPool != nil {
		in, out := &in.LoopbackIpamPool, &out.LoopbackIpamPool
		*out = new(string)
		**out = **in
	}
	if in.OverlayAsPool != nil {
		in, out := &in.OverlayAsPool, &out.OverlayAsPool
		*out = new(string)
		**out = **in
	}
	if in.OverlayProtocol != nil {
		in, out := &in.OverlayProtocol, &out.OverlayProtocol
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.TopologyName != nil {
		in, out := &in.TopologyName, &out.TopologyName
		*out = new(string)
		**out = **in
	}
	if in.UnderlayAsPool != nil {
		in, out := &in.UnderlayAsPool, &out.UnderlayAsPool
		*out = new(string)
		**out = **in
	}
	if in.UnderlayProtocol != nil {
		in, out := &in.UnderlayProtocol, &out.UnderlayProtocol
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InfraInfrastructure.
func (in *InfraInfrastructure) DeepCopy() *InfraInfrastructure {
	if in == nil {
		return nil
	}
	out := new(InfraInfrastructure)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Infrastructure) DeepCopyInto(out *Infrastructure) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Infrastructure.
func (in *Infrastructure) DeepCopy() *Infrastructure {
	if in == nil {
		return nil
	}
	out := new(Infrastructure)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Infrastructure) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InfrastructureList) DeepCopyInto(out *InfrastructureList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Infrastructure, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InfrastructureList.
func (in *InfrastructureList) DeepCopy() *InfrastructureList {
	if in == nil {
		return nil
	}
	out := new(InfrastructureList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *InfrastructureList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InfrastructureSpec) DeepCopyInto(out *InfrastructureSpec) {
	*out = *in
	if in.Infrastructure != nil {
		in, out := &in.Infrastructure, &out.Infrastructure
		*out = new(InfraInfrastructure)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InfrastructureSpec.
func (in *InfrastructureSpec) DeepCopy() *InfrastructureSpec {
	if in == nil {
		return nil
	}
	out := new(InfrastructureSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InfrastructureStatus) DeepCopyInto(out *InfrastructureStatus) {
	*out = *in
	in.ConditionedStatus.DeepCopyInto(&out.ConditionedStatus)
	out.ControllerRef = in.ControllerRef
	if in.Infrastructure != nil {
		in, out := &in.Infrastructure, &out.Infrastructure
		*out = new(NddoinfrastructureInfrastructure)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InfrastructureStatus.
func (in *InfrastructureStatus) DeepCopy() *InfrastructureStatus {
	if in == nil {
		return nil
	}
	out := new(InfrastructureStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Nddoinfrastructure) DeepCopyInto(out *Nddoinfrastructure) {
	*out = *in
	if in.Infrastructure != nil {
		in, out := &in.Infrastructure, &out.Infrastructure
		*out = make([]*NddoinfrastructureInfrastructure, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(NddoinfrastructureInfrastructure)
				(*in).DeepCopyInto(*out)
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Nddoinfrastructure.
func (in *Nddoinfrastructure) DeepCopy() *Nddoinfrastructure {
	if in == nil {
		return nil
	}
	out := new(Nddoinfrastructure)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NddoinfrastructureInfrastructure) DeepCopyInto(out *NddoinfrastructureInfrastructure) {
	*out = *in
	if in.AddressingScheme != nil {
		in, out := &in.AddressingScheme, &out.AddressingScheme
		*out = new(string)
		**out = **in
	}
	if in.AdminState != nil {
		in, out := &in.AdminState, &out.AdminState
		*out = new(string)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.InterfaceTagPool != nil {
		in, out := &in.InterfaceTagPool, &out.InterfaceTagPool
		*out = new(string)
		**out = **in
	}
	if in.IslIpamPool != nil {
		in, out := &in.IslIpamPool, &out.IslIpamPool
		*out = new(string)
		**out = **in
	}
	if in.LoopbackIpamPool != nil {
		in, out := &in.LoopbackIpamPool, &out.LoopbackIpamPool
		*out = new(string)
		**out = **in
	}
	if in.OverlayAsPool != nil {
		in, out := &in.OverlayAsPool, &out.OverlayAsPool
		*out = new(string)
		**out = **in
	}
	if in.OverlayProtocol != nil {
		in, out := &in.OverlayProtocol, &out.OverlayProtocol
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
	if in.State != nil {
		in, out := &in.State, &out.State
		*out = new(NddoinfrastructureInfrastructureState)
		(*in).DeepCopyInto(*out)
	}
	if in.TopologyName != nil {
		in, out := &in.TopologyName, &out.TopologyName
		*out = new(string)
		**out = **in
	}
	if in.UnderlayAsPool != nil {
		in, out := &in.UnderlayAsPool, &out.UnderlayAsPool
		*out = new(string)
		**out = **in
	}
	if in.UnderlayProtocol != nil {
		in, out := &in.UnderlayProtocol, &out.UnderlayProtocol
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NddoinfrastructureInfrastructure.
func (in *NddoinfrastructureInfrastructure) DeepCopy() *NddoinfrastructureInfrastructure {
	if in == nil {
		return nil
	}
	out := new(NddoinfrastructureInfrastructure)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NddoinfrastructureInfrastructureState) DeepCopyInto(out *NddoinfrastructureInfrastructureState) {
	*out = *in
	if in.LastUpdate != nil {
		in, out := &in.LastUpdate, &out.LastUpdate
		*out = new(string)
		**out = **in
	}
	if in.Node != nil {
		in, out := &in.Node, &out.Node
		*out = make([]*NddoinfrastructureInfrastructureStateNode, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(NddoinfrastructureInfrastructureStateNode)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.Link != nil {
		in, out := &in.Link, &out.Link
		*out = make([]*NddoinfrastructureInfrastructureStateLink, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(NddoinfrastructureInfrastructureStateLink)
				**out = **in
			}
		}
	}
	if in.Reason != nil {
		in, out := &in.Reason, &out.Reason
		*out = new(string)
		**out = **in
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NddoinfrastructureInfrastructureState.
func (in *NddoinfrastructureInfrastructureState) DeepCopy() *NddoinfrastructureInfrastructureState {
	if in == nil {
		return nil
	}
	out := new(NddoinfrastructureInfrastructureState)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NddoinfrastructureInfrastructureStateLink) DeepCopyInto(out *NddoinfrastructureInfrastructureStateLink) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NddoinfrastructureInfrastructureStateLink.
func (in *NddoinfrastructureInfrastructureStateLink) DeepCopy() *NddoinfrastructureInfrastructureStateLink {
	if in == nil {
		return nil
	}
	out := new(NddoinfrastructureInfrastructureStateLink)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NddoinfrastructureInfrastructureStateNode) DeepCopyInto(out *NddoinfrastructureInfrastructureStateNode) {
	*out = *in
	if in.Endpoint != nil {
		in, out := &in.Endpoint, &out.Endpoint
		*out = make([]*NddoinfrastructureInfrastructureStateNodeEndpoint, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(NddoinfrastructureInfrastructureStateNodeEndpoint)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NddoinfrastructureInfrastructureStateNode.
func (in *NddoinfrastructureInfrastructureStateNode) DeepCopy() *NddoinfrastructureInfrastructureStateNode {
	if in == nil {
		return nil
	}
	out := new(NddoinfrastructureInfrastructureStateNode)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NddoinfrastructureInfrastructureStateNodeEndpoint) DeepCopyInto(out *NddoinfrastructureInfrastructureStateNodeEndpoint) {
	*out = *in
	if in.Lag != nil {
		in, out := &in.Lag, &out.Lag
		*out = new(bool)
		**out = **in
	}
	if in.LagSubLink != nil {
		in, out := &in.LagSubLink, &out.LagSubLink
		*out = new(bool)
		**out = **in
	}
	if in.Name != nil {
		in, out := &in.Name, &out.Name
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NddoinfrastructureInfrastructureStateNodeEndpoint.
func (in *NddoinfrastructureInfrastructureStateNodeEndpoint) DeepCopy() *NddoinfrastructureInfrastructureStateNodeEndpoint {
	if in == nil {
		return nil
	}
	out := new(NddoinfrastructureInfrastructureStateNodeEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Root) DeepCopyInto(out *Root) {
	*out = *in
	if in.InfraNddoinfrastructure != nil {
		in, out := &in.InfraNddoinfrastructure, &out.InfraNddoinfrastructure
		*out = new(Nddoinfrastructure)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Root.
func (in *Root) DeepCopy() *Root {
	if in == nil {
		return nil
	}
	out := new(Root)
	in.DeepCopyInto(out)
	return out
}