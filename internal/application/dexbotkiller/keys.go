package dexbotkiller

import (
	"fmt"
	"strings"
	"time"
)

type KeyBuilder struct {
	prefix string
	hasher Hasher
}

func NewKeyBuilder(prefix string, hasher Hasher) KeyBuilder {
	if prefix == "" {
		prefix = "dbk:v1"
	}

	return KeyBuilder{
		prefix: strings.TrimSuffix(prefix, ":"),
		hasher: hasher,
	}
}

func (b KeyBuilder) Counter(flow Flow, action FlowAction, dimension string, value string, window time.Duration) string {
	return fmt.Sprintf("%s:counter:%s:%s:%s:%s:%s", b.prefix, flow, action, dimension, b.hasher.Hash(value), windowSuffix(window))
}

func (b KeyBuilder) Unique(flow Flow, action FlowAction, ownerDimension string, ownerValue string, targetDimension string, window time.Duration) string {
	return fmt.Sprintf("%s:uniq:%s:%s:%s_by_%s:%s:%s", b.prefix, flow, action, targetDimension, ownerDimension, b.hasher.Hash(ownerValue), windowSuffix(window))
}

func (b KeyBuilder) Score(dimension string, value string) string {
	return fmt.Sprintf("%s:score:%s:%s", b.prefix, dimension, b.hasher.Hash(value))
}

func (b KeyBuilder) Member(value string) string {
	return b.hasher.Hash(value)
}

func windowSuffix(window time.Duration) string {
	switch {
	case window%time.Hour == 0:
		return fmt.Sprintf("%dh", int(window/time.Hour))
	case window%time.Minute == 0:
		return fmt.Sprintf("%dm", int(window/time.Minute))
	case window%time.Second == 0:
		return fmt.Sprintf("%ds", int(window/time.Second))
	default:
		return fmt.Sprintf("%dms", int(window/time.Millisecond))
	}
}
