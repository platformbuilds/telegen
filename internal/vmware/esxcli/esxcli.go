// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package esxcli

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/types"
)

func ConfigArguments(args map[string]string) []ReflectManagedMethodExecuterSoapArgument {
	sargs := make([]ReflectManagedMethodExecuterSoapArgument, 0, len(args))
	for argName, argValue := range args {
		sargs = append(sargs, ReflectManagedMethodExecuterSoapArgument{
			Name: argName,
			Val:  fmt.Sprintf("<%s>%s</%s>", argName, argValue, argName),
		})
	}
	return sargs
}

func GetHostMME(ctx context.Context, client *vim25.Client, host *types.ManagedObjectReference) (*types.ManagedObjectReference, error) {
	req := RetrieveManagedMethodExecuterRequest{This: *host}
	res, err := RetrieveManagedMethodExecuter(ctx, client, &req)
	if err != nil {
		return nil, fmt.Errorf("retrieve managed method executer: %w", err)
	}
	if res == nil || res.Returnval == nil {
		return nil, fmt.Errorf("retrieve managed method executer: empty response")
	}
	return &res.Returnval.ManagedObjectReference, nil
}

func GetSOAP(ctx context.Context, client *vim25.Client, request *ExecuteSoapRequest, data any) error {
	res, err := ExecuteSoap(ctx, client, request)
	if err != nil {
		return fmt.Errorf("execute soap request: %w", err)
	}
	if res == nil || res.Returnval == nil {
		return fmt.Errorf("execute soap request: empty response")
	}
	if res.Returnval.Fault != nil {
		return fmt.Errorf("esxcli fault: %s", res.Returnval.Fault.FaultMsg)
	}
	if err := xml.Unmarshal([]byte(res.Returnval.Response), data); err != nil {
		return fmt.Errorf("unmarshal esxcli xml response: %w", err)
	}
	return nil
}
