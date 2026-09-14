// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package logfilter registers the policy driver for
// google.telemetry.policy.v1alpha1.LogFilterPolicy.
//
// It is the bridge between a policy as it arrives from a control plane (a
// generic map decoded from an xDS resource or a config file) and the typed
// protobuf message that googlepolicyprocessor's evaluator compiles and runs.
package logfilter

import (
	"encoding/json"
	"errors"
	"fmt"

	policyv1alpha1 "github.com/GoogleCloudPlatform/opentelemetry-operations-collector/gen/go/policy/v1alpha1"
	"github.com/GoogleCloudPlatform/opentelemetry-operations-collector/pkg/googlepolicy"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func init() {
	googlepolicy.RegisterPolicyDriver(PolicyType, &Driver{})
}

// PolicyType is the discriminator this driver registers under.
//
// It must match the value the policy manager puts in the raw policy's "type"
// field. For policies delivered over xDS that value is derived from the last
// segment of the typed_config type URL, i.e.
// "type.googleapis.com/google.telemetry.policy.v1alpha1.LogFilterPolicy"
// yields "LogFilterPolicy". Config-file policies must therefore spell the type
// the same way.
const PolicyType = "LogFilterPolicy"

// Keys the policy manager injects into the raw policy map from the enclosing
// xDS TypedExtensionConfig. They are not fields of LogFilterPolicy, so they are
// removed before the body is handed to protojson, which rejects unknown fields.
const (
	rawKeyName = "name"
	rawKeyType = "type"
)

var (
	ErrPolicyMissingID          = errors.New("log filter policy has no 'id'")
	ErrPolicyMissingMatchers    = errors.New("log filter policy has no matchers: a policy that matches nothing is never valid")
	ErrPolicyMissingAction      = errors.New("log filter policy has no action: expected ACTION_KEEP or ACTION_DROP")
	ErrPolicyMatcherNoTarget    = errors.New("log filter policy matcher has no target")
	ErrPolicyMatcherNoPredicate = errors.New("log filter policy matcher has no predicate")
)

// LogFilterPolicy adapts the LogFilterPolicy protobuf message to the
// googlepolicy interfaces.
//
// The message is carried through unmodified and handed to the processor via
// Proto(); this type deliberately does not reinterpret the policy body, so the
// evaluator remains the single source of truth for filter semantics.
type LogFilterPolicy struct {
	pb *policyv1alpha1.LogFilterPolicy

	// fallbackName is the name from the enclosing TypedExtensionConfig, used
	// only when the policy body carries no id of its own.
	fallbackName string
}

var (
	_ googlepolicy.TransformationPolicy = (*LogFilterPolicy)(nil)
	// Structurally satisfies googlepolicyprocessor.ProtoPolicy. That interface
	// is not imported here: the processor consumes the provider's policies, so
	// depending on it in this direction would be a cycle.
	_ interface{ Proto() proto.Message } = (*LogFilterPolicy)(nil)
)

// PolicyName identifies the policy within a policy set.
//
// The policy's own id is preferred over the enclosing extension name, because
// PolicySet is keyed by this value: several log filter policies typically
// arrive under one extension name, and using that name would collapse them
// into a single entry.
func (p *LogFilterPolicy) PolicyName() string {
	if id := p.pb.GetId(); id != "" {
		return id
	}
	return p.fallbackName
}

func (p *LogFilterPolicy) PolicyType() string {
	return PolicyType
}

func (p *LogFilterPolicy) PolicyClass() googlepolicy.PolicyClass {
	return googlepolicy.PolicyClassTransformation
}

// TargetSignals reports that this policy only ever applies to logs.
func (p *LogFilterPolicy) TargetSignals() []googlepolicy.Signal {
	return []googlepolicy.Signal{googlepolicy.SignalLogs}
}

// Proto returns the underlying message for googlepolicyprocessor to compile.
func (p *LogFilterPolicy) Proto() proto.Message {
	return p.pb
}

// Validate rejects policies that would compile into a no-op or an ambiguous
// filter. It is intentionally strict: a malformed policy is NACKed back to the
// control plane, which is far easier to debug than telemetry silently passing
// through or disappearing.
func (p *LogFilterPolicy) Validate() error {
	if p.pb.GetId() == "" {
		return ErrPolicyMissingID
	}
	if p.pb.GetAction() == policyv1alpha1.Action_ACTION_UNSPECIFIED {
		return fmt.Errorf("%w: policy %q", ErrPolicyMissingAction, p.pb.GetId())
	}
	if len(p.pb.GetMatches()) == 0 {
		return fmt.Errorf("%w: policy %q", ErrPolicyMissingMatchers, p.pb.GetId())
	}
	for i, m := range p.pb.GetMatches() {
		if m.GetTarget() == nil {
			return fmt.Errorf("%w: policy %q matcher %d", ErrPolicyMatcherNoTarget, p.pb.GetId(), i)
		}
		if m.GetPredicate() == nil {
			return fmt.Errorf("%w: policy %q matcher %d", ErrPolicyMatcherNoPredicate, p.pb.GetId(), i)
		}
	}
	return nil
}

// Driver loads LogFilterPolicy objects from the generic map representation.
type Driver struct{}

var _ googlepolicy.PolicyDriver = (*Driver)(nil)

// LoadPolicy decodes a raw policy map into a LogFilterPolicy.
//
// The map is round-tripped back through JSON into protojson rather than
// decoded with mapstructure, because LogFilterPolicy relies on oneof
// predicates, google.protobuf.Empty, and enum-by-name encoding, none of which
// mapstructure can represent. This mirrors how the policy manager produced the
// map in the first place (protojson -> map), so the round trip is lossless.
func (d *Driver) LoadPolicy(raw map[string]any) (googlepolicy.Policy, error) {
	body := make(map[string]any, len(raw))
	for k, v := range raw {
		if k == rawKeyName || k == rawKeyType {
			continue
		}
		body[k] = v
	}

	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode log filter policy: %w", err)
	}

	pb := &policyv1alpha1.LogFilterPolicy{}
	if err := protojson.Unmarshal(b, pb); err != nil {
		return nil, fmt.Errorf("failed to decode log filter policy: %w", err)
	}

	name, _ := raw[rawKeyName].(string)
	return &LogFilterPolicy{pb: pb, fallbackName: name}, nil
}
