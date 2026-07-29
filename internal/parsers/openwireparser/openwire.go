// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package openwireparser implements a bounded parser for ActiveMQ OpenWire traffic.
package openwireparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/openwireparser"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNeedsMoreData = errors.New("openwire: needs more data")
	MagicActiveMQ    = []byte("ActiveMQ")
)

type CommandType uint8

const (
	CommandUnknown        CommandType = 0
	CommandWireFormatInfo CommandType = 1
	CommandConsumerInfo   CommandType = 5
	CommandProducerInfo   CommandType = 6
	CommandMessageAck     CommandType = 22
	CommandMessage        CommandType = 23
)

type DestinationType uint8

const (
	DestinationUnknown DestinationType = 0
	DestinationQueue   DestinationType = 1
	DestinationTopic   DestinationType = 2
)

type Command struct {
	Type            CommandType
	ProducerID      uint32
	ConsumerID      uint32
	Destination     string
	DestinationType DestinationType
}

func IsOpenWire(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	if bytes.Contains(buf, MagicActiveMQ) {
		return true
	}
	cmd, _, err := ParseCommand(buf)
	return err == nil && cmd.Type != CommandUnknown
}

func ParseCommands(buf []byte) ([]Command, int, error) {
	commands := make([]Command, 0, 4)
	consumed := 0
	for len(buf) > 0 {
		command, n, err := ParseCommand(buf)
		if errors.Is(err, ErrNeedsMoreData) {
			break
		}
		if err != nil {
			return commands, consumed, err
		}
		commands = append(commands, command)
		buf = buf[n:]
		consumed += n
	}
	return commands, consumed, nil
}

func ParseCommand(buf []byte) (Command, int, error) {
	if len(buf) < 1 {
		return Command{}, 0, ErrNeedsMoreData
	}
	cmdType := CommandType(buf[0])
	switch cmdType {
	case CommandWireFormatInfo:
		return parseWireFormatInfo(buf)
	case CommandProducerInfo:
		return parseProducerInfo(buf)
	case CommandConsumerInfo:
		return parseConsumerInfo(buf)
	case CommandMessage:
		return parseMessage(buf)
	case CommandMessageAck:
		return parseMessageAck(buf)
	default:
		return Command{}, 0, fmt.Errorf("openwire: unsupported command type %d", cmdType)
	}
}

func parseWireFormatInfo(buf []byte) (Command, int, error) {
	if len(buf) < 3 {
		return Command{}, 0, ErrNeedsMoreData
	}
	nameLen := int(binary.BigEndian.Uint16(buf[1:3]))
	if len(buf) < 3+nameLen {
		return Command{}, 0, ErrNeedsMoreData
	}
	name := string(buf[3 : 3+nameLen])
	if !strings.Contains(name, "ActiveMQ") {
		return Command{}, 0, errors.New("openwire: wireformat magic missing ActiveMQ")
	}
	return Command{Type: CommandWireFormatInfo}, 3 + nameLen, nil
}

func parseProducerInfo(buf []byte) (Command, int, error) {
	if len(buf) < 8 {
		return Command{}, 0, ErrNeedsMoreData
	}
	producerID := binary.BigEndian.Uint32(buf[1:5])
	destType := parseDestinationType(buf[5])
	destination, consumed, err := parseString(buf, 6)
	if err != nil {
		return Command{}, 0, err
	}
	return Command{
		Type:            CommandProducerInfo,
		ProducerID:      producerID,
		DestinationType: destType,
		Destination:     destination,
	}, consumed, nil
}

func parseConsumerInfo(buf []byte) (Command, int, error) {
	if len(buf) < 8 {
		return Command{}, 0, ErrNeedsMoreData
	}
	consumerID := binary.BigEndian.Uint32(buf[1:5])
	destType := parseDestinationType(buf[5])
	destination, consumed, err := parseString(buf, 6)
	if err != nil {
		return Command{}, 0, err
	}
	return Command{
		Type:            CommandConsumerInfo,
		ConsumerID:      consumerID,
		DestinationType: destType,
		Destination:     destination,
	}, consumed, nil
}

func parseMessage(buf []byte) (Command, int, error) {
	if len(buf) < 8 {
		return Command{}, 0, ErrNeedsMoreData
	}
	producerID := binary.BigEndian.Uint32(buf[1:5])
	destType := parseDestinationType(buf[5])
	destination, consumed, err := parseString(buf, 6)
	if err != nil {
		return Command{}, 0, err
	}
	return Command{
		Type:            CommandMessage,
		ProducerID:      producerID,
		DestinationType: destType,
		Destination:     destination,
	}, consumed, nil
}

func parseMessageAck(buf []byte) (Command, int, error) {
	if len(buf) < 5 {
		return Command{}, 0, ErrNeedsMoreData
	}
	return Command{
		Type:       CommandMessageAck,
		ConsumerID: binary.BigEndian.Uint32(buf[1:5]),
	}, 5, nil
}

func parseString(buf []byte, offset int) (string, int, error) {
	if len(buf) < offset+2 {
		return "", 0, ErrNeedsMoreData
	}
	n := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
	if len(buf) < offset+2+n {
		return "", 0, ErrNeedsMoreData
	}
	return string(buf[offset+2 : offset+2+n]), offset + 2 + n, nil
}

func parseDestinationType(raw byte) DestinationType {
	switch raw {
	case byte(DestinationQueue):
		return DestinationQueue
	case byte(DestinationTopic):
		return DestinationTopic
	default:
		return DestinationUnknown
	}
}
