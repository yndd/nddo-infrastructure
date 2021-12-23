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
	"fmt"
	"reflect"
	"strings"

	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/resource"
	ipamv1alpha1 "github.com/yndd/nddr-ipam/apis/ipam/v1alpha1"
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
		ipv4:  make(map[string]AddressInfo),
		ipv6:  make(map[string]AddressInfo),
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
	GetAddressesInfo(af string) map[string]AddressInfo
	Print(string, int)
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
	innerTag *uint32
	ipv4     map[string]AddressInfo
	ipv6     map[string]AddressInfo
}

func (x *subInterface) GetInterface() Interface {
	return x.itfce
}

func (x *subInterface) GetName() string {
	if reflect.ValueOf(x.name).IsZero() {
		return ""
	}
	return *x.name
}

func (x *subInterface) GetNeighbor() SubInterface {
	return x.neighbor
}

func (x *subInterface) GetTaggingKind() string {
	return string(x.tagging)
}

func (x *subInterface) GetKind() string {
	return string(x.kind)
}

func (x *subInterface) GetOuterTag() uint32 {
	if reflect.ValueOf(x.outerTag).IsZero() {
		return 0
	}
	return *x.outerTag
}

func (x *subInterface) GetInnerTag() uint32 {
	if reflect.ValueOf(x.innerTag).IsZero() {
		return 0
	}
	return *x.innerTag
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
	x.innerTag = &t
}

func (x *subInterface) SetOuterTag(t uint32) {
	x.outerTag = &t
}

func (x *subInterface) GetAddressesInfo(af string) map[string]AddressInfo {
	switch af {
	case string(ipamv1alpha1.AddressFamilyIpv4):
		return x.ipv4
	case string(ipamv1alpha1.AddressFamilyIpv6):
		return x.ipv6
	}
	return nil
}

func (x *subInterface) GetIpv6AddressesInfo() map[string]AddressInfo {
	return x.ipv6
}

func (x *subInterface) Print(subItfceName string, n int) {
	fmt.Printf("%s SubInterface: %s Kind: %s Tagging: %s\n", strings.Repeat(" ", n), subItfceName, x.GetKind(), x.GetTaggingKind())
	n++
	fmt.Printf("%s Local Addressing Info\n", strings.Repeat(" ", n))
	for prefix, i := range x.ipv4 {
		i.Print(string(ipamv1alpha1.AddressFamilyIpv4), prefix, n)
	}
	for prefix, i := range x.ipv6 {
		i.Print(string(ipamv1alpha1.AddressFamilyIpv6), prefix, n)
	}
	if x.neighbor != nil {
		fmt.Printf("%s Neighbor Addressing Info\n", strings.Repeat(" ", n))
		for prefix, i := range x.neighbor.GetAddressesInfo(string(ipamv1alpha1.AddressFamilyIpv4)) {
			i.Print(string(ipamv1alpha1.AddressFamilyIpv4), prefix, n)
		}
		for prefix, i := range x.neighbor.GetAddressesInfo(string(ipamv1alpha1.AddressFamilyIpv6)) {
			i.Print(string(ipamv1alpha1.AddressFamilyIpv6), prefix, n)
		}
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
