// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import "testing"

func TestResolveAMQP091MessagingSystem(t *testing.T) {
	if got := ResolveAMQP091MessagingSystem(); got != messagingSystemRabbitMQ {
		t.Fatalf("ResolveAMQP091MessagingSystem() = %q, want %q", got, messagingSystemRabbitMQ)
	}
}

func TestResolveAMQP1MessagingSystem(t *testing.T) {
	tests := []struct {
		name  string
		hints []string
		want  string
	}{
		{name: "empty hints defaults to activemq", hints: nil, want: messagingSystemActiveMQ},
		{name: "service bus token", hints: []string{"Azure-ServiceBus-Processor"}, want: messagingSystemServiceBus},
		{name: "activemq token", hints: []string{"activemq-artemis"}, want: messagingSystemActiveMQ},
		{name: "activemq port hint", hints: []string{"port:61616"}, want: messagingSystemActiveMQ},
		{name: "rabbit token", hints: []string{"rabbitmq"}, want: messagingSystemRabbitMQ},
		{name: "rabbit port hint", hints: []string{"port:5672"}, want: messagingSystemRabbitMQ},
		{name: "beam token", hints: []string{"beam.smp"}, want: messagingSystemRabbitMQ},
		{name: "qpid token", hints: []string{"apache-qpid"}, want: messagingSystemJMS},
		{name: "solace token", hints: []string{"solace-router"}, want: messagingSystemJMS},
		{name: "unknown keeps default", hints: []string{"custom-broker"}, want: messagingSystemActiveMQ},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveAMQP1MessagingSystem(tt.hints...)
			if got != tt.want {
				t.Fatalf("ResolveAMQP1MessagingSystem() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveOpenWireMessagingSystem(t *testing.T) {
	if got := ResolveOpenWireMessagingSystem(); got != messagingSystemActiveMQ {
		t.Fatalf("ResolveOpenWireMessagingSystem() = %q, want %q", got, messagingSystemActiveMQ)
	}
}

func TestResolveSTOMPMessagingSystem(t *testing.T) {
	tests := []struct {
		name  string
		hints []string
		want  string
	}{
		{name: "empty hints defaults to activemq", hints: nil, want: messagingSystemActiveMQ},
		{name: "service bus token", hints: []string{"servicebus-gateway"}, want: messagingSystemServiceBus},
		{name: "stomp port hint", hints: []string{"port:61613"}, want: messagingSystemActiveMQ},
		{name: "rabbit token", hints: []string{"beam.smp"}, want: messagingSystemRabbitMQ},
		{name: "solace token", hints: []string{"solace-broker"}, want: messagingSystemJMS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveSTOMPMessagingSystem(tt.hints...)
			if got != tt.want {
				t.Fatalf("ResolveSTOMPMessagingSystem() = %q, want %q", got, tt.want)
			}
		})
	}
}
