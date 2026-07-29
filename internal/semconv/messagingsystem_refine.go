// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import (
	"strings"

	otelsemconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

var (
	messagingSystemActiveMQ   = otelsemconv.MessagingSystemActiveMQ.Value.AsString()
	messagingSystemServiceBus = otelsemconv.MessagingSystemServiceBus.Value.AsString()
	messagingSystemJMS        = otelsemconv.MessagingSystemJMS.Value.AsString()
	messagingSystemRabbitMQ   = otelsemconv.MessagingSystemRabbitMQ.Value.AsString()
)

// ResolveAMQP091MessagingSystem always maps AMQP 0-9-1 to RabbitMQ.
func ResolveAMQP091MessagingSystem() string {
	return messagingSystemRabbitMQ
}

// ResolveAMQP1MessagingSystem maps AMQP 1.0 systems using executable/workload hints.
func ResolveAMQP1MessagingSystem(hints ...string) string {
	return resolveMQSystemFromHints(messagingSystemActiveMQ, hints...)
}

// ResolveOpenWireMessagingSystem always maps OpenWire to ActiveMQ.
func ResolveOpenWireMessagingSystem() string {
	return messagingSystemActiveMQ
}

// ResolveSTOMPMessagingSystem maps STOMP systems using executable/workload hints.
func ResolveSTOMPMessagingSystem(hints ...string) string {
	return resolveMQSystemFromHints(messagingSystemActiveMQ, hints...)
}

func resolveMQSystemFromHints(defaultSystem string, hints ...string) string {
	combined := strings.ToLower(strings.Join(hints, " "))
	if combined == "" {
		return defaultSystem
	}

	if strings.Contains(combined, "servicebus") || strings.Contains(combined, "azure-servicebus") {
		return messagingSystemServiceBus
	}
	if strings.Contains(combined, "artemis") ||
		strings.Contains(combined, "activemq") ||
		strings.Contains(combined, "openwire") ||
		strings.Contains(combined, "stomp") ||
		strings.Contains(combined, "port:61616") ||
		strings.Contains(combined, "port:61617") ||
		strings.Contains(combined, "port:61613") ||
		strings.Contains(combined, "port:61614") {
		return messagingSystemActiveMQ
	}
	if strings.Contains(combined, "rabbit") ||
		strings.Contains(combined, "beam.smp") ||
		strings.Contains(combined, "port:5672") ||
		strings.Contains(combined, "port:5671") {
		return messagingSystemRabbitMQ
	}
	if strings.Contains(combined, "qpid") || strings.Contains(combined, "solace") {
		return messagingSystemJMS
	}

	return defaultSystem
}
