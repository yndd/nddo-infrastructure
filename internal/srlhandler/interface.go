package srlhandler

import (
	"context"

	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/nddo-runtime/pkg/resource"
	schema "github.com/yndd/nddp-srl/pkg/srlschema/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Option can be used to manipulate Options.
type Option func(Handler)

// WithLogger specifies how the Reconciler should log messages.
func WithLogger(log logging.Logger) Option {
	return func(s Handler) {
		s.WithLogger(log)
	}
}

func WithClient(c client.Client) Option {
	return func(s Handler) {
		s.WithClient(c)
	}
}

type Handler interface {
	WithLogger(log logging.Logger)
	WithClient(c client.Client)
	InitSchema(crName string) schema.Schema
	DestroySchema(crName string)
	DeploySchema(ctx context.Context, mg resource.Managed, labels map[string]string) error
	ValidateSchema(ctx context.Context, mg resource.Managed) error
	PrintDevices(string)
}
