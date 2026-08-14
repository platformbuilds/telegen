//go:build linux && cgo

package host

import (
	"fmt"
	"log/slog"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
)

// appendGPU collects per-GPU metrics via NVIDIA NVML.
// It is a no-op on non-NVIDIA hosts (NVML init failure is silently ignored).
//
// Metrics emitted:
//
//	system_gpu_utilization_ratio{gpu_index, gpu_name, gpu_uuid}
//	system_gpu_memory_used_bytes{gpu_index, gpu_name, gpu_uuid}
//	system_gpu_memory_total_bytes{gpu_index, gpu_name, gpu_uuid}
//	system_gpu_temperature_celsius{gpu_index, gpu_name, gpu_uuid}
func (c *Collector) appendGPU(wr *prompb.WriteRequest) {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		// No NVIDIA GPU or driver not installed — silently skip.
		return
	}
	defer func() {
		if r := nvml.Shutdown(); r != nvml.SUCCESS {
			slog.Debug("NVML shutdown error", "err", nvml.ErrorString(r))
		}
	}()

	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		slog.Debug("NVML DeviceGetCount failed", "err", nvml.ErrorString(ret))
		return
	}

	for i := 0; i < count; i++ {
		dev, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			continue
		}
		name, ret := nvml.DeviceGetName(dev)
		if ret != nvml.SUCCESS {
			name = "unknown"
		}
		uuid, ret := nvml.DeviceGetUUID(dev)
		if ret != nvml.SUCCESS {
			uuid = "unknown"
		}

		lbls := c.baseLabels(
			labels.Label{Name: "gpu_index", Value: fmt.Sprintf("%d", i)},
			labels.Label{Name: "gpu_name", Value: name},
			labels.Label{Name: "gpu_uuid", Value: uuid},
		)

		// Utilization rates (%GPU, %memory encoder/decoder)
		util, ret := nvml.DeviceGetUtilizationRates(dev)
		if ret == nvml.SUCCESS {
			c.appendPoint(wr, "system_gpu_utilization_ratio", lbls, float64(util.Gpu)/100.0)
		}

		// Memory info (used / total bytes)
		memInfo, ret := nvml.DeviceGetMemoryInfo(dev)
		if ret == nvml.SUCCESS {
			c.appendPoint(wr, "system_gpu_memory_used_bytes", lbls, float64(memInfo.Used))
			c.appendPoint(wr, "system_gpu_memory_total_bytes", lbls, float64(memInfo.Total))
		}

		// Temperature (GPU sensor)
		temp, ret := nvml.DeviceGetTemperature(dev, nvml.TEMPERATURE_GPU)
		if ret == nvml.SUCCESS {
			c.appendPoint(wr, "system_gpu_temperature_celsius", lbls, float64(temp))
		}
	}
}
