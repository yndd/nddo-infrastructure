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
	"github.com/yndd/ndd-runtime/pkg/utils"
)

// InfraOption is used to configure the Infra.
type InterfaceOption func(*itfce)

func WithInterfaceLogger(log logging.Logger) InterfaceOption {
	return func(r *itfce) {
		r.log = log
	}
}

func WithInterfaceClient(c resource.ClientApplicator) InterfaceOption {
	return func(r *itfce) {
		r.client = c
	}
}

func NewInterface(n Node, opts ...InterfaceOption) Interface {
	i := &itfce{
		node:          n,
		subInterfaces: make([]SubInterface, 0),
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ Interface = &itfce{}

type Interface interface {
	GetNode() Node
	GetName() string
	GetKind() string
	IsLag() bool
	IsLagMember() bool
	GetLagName() string
	SetNode(Node)
	SetName(string)
	SetKind(InterfaceKind)
	SetLag()
	SetLagMember()
	SetLagName(string)
	GetLagMembers() []Interface
	GetLagMemberNames() []string
	HasVlanTags() bool
	GetSubInterfaces() []SubInterface
	GetSubInterface(string) SubInterface
	AddSubInterface(SubInterface)
	DeleteSubInterface(SubInterface)
}

type itfce struct {
	client resource.ClientApplicator
	log    logging.Logger

	node          Node
	name          *string
	kind          InterfaceKind
	lag           *bool
	lagMember     *bool
	lagName       *string
	subInterfaces []SubInterface
}

func (x *itfce) GetNode() Node {
	return x.node
}

func (x *itfce) GetName() string {
	return *x.name
}

func (x *itfce) GetKind() string {
	return x.kind.String()
}

func (x *itfce) IsLag() bool {
	return *x.lag
}

func (x *itfce) IsLagMember() bool {
	return *x.lagMember
}

func (x *itfce) GetLagName() string {
	return *x.lagName
}

func (x *itfce) SetNode(n Node) {
	x.node = n
}

func (x *itfce) SetName(n string) {
	x.name = &n
}

func (x *itfce) SetKind(n InterfaceKind) {
	x.kind = n
}

func (x *itfce) SetLag() {
	x.lag = utils.BoolPtr(true)
}

func (x *itfce) SetLagMember() {
	x.lagMember = utils.BoolPtr(true)
}

func (x *itfce) SetLagName(n string) {
	x.lagName = &n
}

func (x *itfce) GetLagMembers() []Interface {
	is := make([]Interface, 0)
	if *x.lagName != "" {
		for _, i := range x.node.GetInterfaces() {
			if i.IsLagMember() && i.GetLagName() == *x.lagName {
				is = append(is, i)
			}
		}
	}
	return is
}

func (x *itfce) GetLagMemberNames() []string {
	is := make([]string, 0)
	if *x.lagName != "" {
		for _, i := range x.node.GetInterfaces() {
			if i.IsLagMember() && i.GetLagName() == *x.lagName {
				is = append(is, i.GetName())
			}
		}
	}
	return is
}

func (x *itfce) GetSubInterfaces() []SubInterface {
	return x.subInterfaces
}

func (x *itfce) GetSubInterface(n string) SubInterface {
	for _, i := range x.subInterfaces {
		if i.GetName() == n {
			return i
		}
	}
	return nil
}

func (x *itfce) AddSubInterface(n SubInterface) {
	for _, i := range x.subInterfaces {
		if i.GetName() == n.GetName() {
			i = n
			return
		}
	}
	x.subInterfaces = append(x.subInterfaces, n)
}

func (x *itfce) DeleteSubInterface(n SubInterface) {
	found := false
	idx := 0
	for i, si := range x.subInterfaces {
		if si.GetName() == n.GetName() {
			idx = i
			found = true
		}
	}
	if found {
		x.subInterfaces = append(append(x.subInterfaces[:idx], x.subInterfaces[idx+1:]...))
	}
}

func (x *itfce) DeleteInterface(n SubInterface) {
	found := false
	idx := 0
	for i, si := range x.subInterfaces {
		if si.GetName() == n.GetName() {
			idx = i
			found = true
		}
	}
	if found {
		x.subInterfaces = append(append(x.subInterfaces[:idx], x.subInterfaces[idx+1:]...))
	}
}

func (x *itfce) HasVlanTags() bool {
	//for _, s := range x.subInterfaces {
	//
	//}
	return false
}

type InterfaceKind string

const (
	InterfaceKindLoopback   InterfaceKind = "loopback"
	InterfaceKindManagement InterfaceKind = "management"
	InterfaceKindInterface  InterfaceKind = "interface"
)

func (s InterfaceKind) String() string {
	switch s {
	case InterfaceKindManagement:
		return "management"
	case InterfaceKindLoopback:
		return "loopback"
	case InterfaceKindInterface:
		return "interface"
	}
	return "unknown"
}
