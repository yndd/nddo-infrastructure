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

// AddressOption is used to configure the Infra.
type AddressOption func(*addressInfo)

func WithAddressLogger(log logging.Logger) AddressOption {
	return func(r *addressInfo) {
		r.log = log
	}
}

func WithAddressClient(c resource.ClientApplicator) AddressOption {
	return func(r *addressInfo) {
		r.client = c
	}
}

func NewAddressInfo(opts ...AddressOption) AddressInfo {
	i := &addressInfo{}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ AddressInfo = &addressInfo{}

type AddressInfo interface {
	GetPrefix() string
	GetAddress() string
	GetPrefixLength() uint32
	SetPrefix(string)
	SetAddress(string)
	SetPrefixLength(uint32)
}

type addressInfo struct {
	client resource.ClientApplicator
	log    logging.Logger

	prefix       *string
	address      *string
	prefixLength *uint32
}

func (x *addressInfo) GetPrefix() string {
	return *x.prefix
}

func (x *addressInfo) GetAddress() string {
	return *x.address
}

func (x *addressInfo) GetPrefixLength() uint32 {
	return *x.prefixLength
}

func (x *addressInfo) SetPrefix(s string) {
	x.prefix = &s
}

func (x *addressInfo) SetAddress(s string) {
	x.address = &s
}

func (x *addressInfo) SetPrefixLength(s uint32) {
	x.prefixLength = &s
}
