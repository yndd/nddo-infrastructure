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
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/resource"
)

// InfraOption is used to configure the Infra.
type SubInterfaceOption func(*subInterface)

func WithSubInterfaceLogger(log logging.Logger) SubInterfaceOption {
	return func(r *subInterface) {
		r.log = log
	}
}

func WithSubInterfaceClient(c resource.ClientApplicator) SubInterfaceOption {
	return func(r *subInterface) {
		r.client = c
	}
}

func NewSubInterface(itfce Interface, opts ...SubInterfaceOption) SubInterface {
	i := &subInterface{
		itfce: itfce,
		ipv4:  make([]AddressInfo, 0),
		ipv6:  make([]AddressInfo, 0),
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ SubInterface = &subInterface{}

type SubInterface interface {
	GetInterface() Interface
	GetName() string
	GetNeighbor() SubInterface
	GetTaggingKind() string
	GetKind() string
	GetOuterTag() uint32
	GetInnerTag() uint32
	SetName(string)
	SetNeighbor(SubInterface)
	SetTaggingKind(TaggingKind)
	SetKind(SubInterfaceKind)
	SetOuterTag(uint32)
	SetInnerTag(uint32)
	GetIpv4AddressesInfo() []AddressInfo
	GetIpv6AddressesInfo() []AddressInfo
	GetIpv4AddressInfo(n string) AddressInfo
	GetIpv6AddressInfo(n string) AddressInfo
	AddIpv4AddressInfo(n AddressInfo)
	AddIpv6AddressInfo(n AddressInfo)
	DeleteIpv4AddressInfo(n AddressInfo)
	DeleteIpv6AddressInfo(n AddressInfo)
}

type subInterface struct {
	client resource.ClientApplicator
	log    logging.Logger

	itfce    Interface
	name     *string
	neighbor SubInterface
	tagging  TaggingKind
	kind     SubInterfaceKind
	outerTag *uint32
	innertag *uint32
	ipv4     []AddressInfo
	ipv6     []AddressInfo
}

func (x *subInterface) GetInterface() Interface {
	return x.itfce
}

func (x *subInterface) GetName() string {
	return *x.name
}

func (x *subInterface) GetNeighbor() SubInterface {
	return x.neighbor
}

func (x *subInterface) GetTaggingKind() string {
	return string(x.tagging)
}

func (x *subInterface) GetKind() string {
	return string(x.tagging)
}

func (x *subInterface) GetOuterTag() uint32 {
	return *x.outerTag
}

func (x *subInterface) GetInnerTag() uint32 {
	return *x.innertag
}

func (x *subInterface) SetInterface(i Interface) {
	x.itfce = i
}

func (x *subInterface) SetName(n string) {
	x.name = &n
}

func (x *subInterface) SetNeighbor(n SubInterface) {
	x.neighbor = n
}

func (x *subInterface) SetTaggingKind(n TaggingKind) {
	x.tagging = n
}

func (x *subInterface) SetKind(n SubInterfaceKind) {
	x.kind = n
}

func (x *subInterface) SetInnerTag(t uint32) {
	x.innertag = &t
}

func (x *subInterface) SetOuterTag(t uint32) {
	x.outerTag = &t
}

func (x *subInterface) GetIpv4AddressesInfo() []AddressInfo {
	return x.ipv4
}

func (x *subInterface) GetIpv6AddressesInfo() []AddressInfo {
	return x.ipv4
}

func (x *subInterface) GetIpv4AddressInfo(n string) AddressInfo {
	for _, a := range x.ipv4 {
		if a.GetPrefix() == n {
			return a
		}
	}
	return nil
}

func (x *subInterface) GetIpv6AddressInfo(n string) AddressInfo {
	for _, a := range x.ipv6 {
		if a.GetPrefix() == n {
			return a
		}
	}
	return nil
}

func (x *subInterface) AddIpv4AddressInfo(n AddressInfo) {
	for _, a := range x.ipv4 {
		if a.GetPrefix() == n.GetPrefix() {
			a = n
			return
		}
	}
	x.ipv4 = append(x.ipv4, n)
}

func (x *subInterface) AddIpv6AddressInfo(n AddressInfo) {
	for _, a := range x.ipv6 {
		if a.GetPrefix() == n.GetPrefix() {
			a = n
			return
		}
	}
	x.ipv4 = append(x.ipv6, n)
}

func (x *subInterface) DeleteIpv4AddressInfo(n AddressInfo) {
	found := false
	idx := 0
	for i, a := range x.ipv4 {
		if a.GetPrefix() == n.GetPrefix() {
			idx = i
			found = true
		}
	}
	if found {
		x.ipv4 = append(append(x.ipv4[:idx], x.ipv4[idx+1:]...))
	}
}

func (x *subInterface) DeleteIpv6AddressInfo(n AddressInfo) {
	found := false
	idx := 0
	for i, a := range x.ipv6 {
		if a.GetPrefix() == n.GetPrefix() {
			idx = i
			found = true
		}
	}
	if found {
		x.ipv6 = append(append(x.ipv6[:idx], x.ipv6[idx+1:]...))
	}
}

type SubInterfaceKind string

const (
	SubInterfaceKindBridged SubInterfaceKind = "bridged"
	SubInterfaceKindRouted  SubInterfaceKind = "routed"
)

func (s SubInterfaceKind) String() string {
	switch s {
	case SubInterfaceKindBridged:
		return "bridged"
	case SubInterfaceKindRouted:
		return "routed"
	}
	return "routed"
}

type TaggingKind string

const (
	TaggingKindUnTagged     TaggingKind = "untagged"
	TaggingKindSingleTagged TaggingKind = "singleTagged"
	TaggingKindDoubleTagged TaggingKind = "doubleTagged"
)

func (s TaggingKind) String() string {
	switch s {
	case TaggingKindUnTagged:
		return "untagged"
	case TaggingKindSingleTagged:
		return "singleTagged"
	case TaggingKindDoubleTagged:
		return "doubleTagged"
	}
	return "untagged"
}
