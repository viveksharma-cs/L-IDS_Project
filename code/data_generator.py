"""
data_generator.py — Simulates hypervisor-level VM resource metrics.

This module generates realistic CPU, memory, disk I/O, and network traffic
data for virtual machines, with the ability to inject various attack patterns
(DoS, brute-force, ransomware, cryptomining) into the data stream.
"""

import numpy as np
import time
from datetime import datetime


class VMMetricsGenerator:
    """Generates simulated VM resource metrics with optional attack injection."""

    def __init__(self, vm_id="VM-001", seed=None):
        self.vm_id = vm_id
        self.rng = np.random.default_rng(seed)
        self.tick = 0
        self.attack_active = None
        self.attack_start = 0
        self.attack_duration = 0

        # Baseline parameters for normal operation
        self.baselines = {
            "cpu": {"mean": 25.0, "std": 8.0, "min": 2.0, "max": 100.0},
            "memory": {"mean": 45.0, "std": 5.0, "min": 20.0, "max": 100.0},
            "disk_io": {"mean": 150.0, "std": 40.0, "min": 5.0, "max": 2000.0},
            "network": {"mean": 500.0, "std": 120.0, "min": 10.0, "max": 50000.0},
        }

    def _clamp(self, value, vmin, vmax):
        return max(vmin, min(vmax, value))

    def _normal_metrics(self):
        """Generate one sample of normal VM behavior."""
        # Add a slight diurnal pattern using sine wave
        hour_factor = 1.0 + 0.3 * np.sin(2 * np.pi * self.tick / 3600)

        cpu = self.rng.normal(
            self.baselines["cpu"]["mean"] * hour_factor,
            self.baselines["cpu"]["std"],
        )
        memory = self.rng.normal(
            self.baselines["memory"]["mean"],
            self.baselines["memory"]["std"],
        )
        disk_io = self.rng.normal(
            self.baselines["disk_io"]["mean"] * hour_factor,
            self.baselines["disk_io"]["std"],
        )
        network = self.rng.normal(
            self.baselines["network"]["mean"] * hour_factor,
            self.baselines["network"]["std"],
        )

        return {
            "cpu": self._clamp(cpu, 2, 100),
            "memory": self._clamp(memory, 20, 100),
            "disk_io": self._clamp(disk_io, 5, 2000),
            "network": self._clamp(network, 10, 50000),
        }

    def inject_attack(self, attack_type, duration=60):
        """Start injecting an attack pattern into the data stream."""
        self.attack_active = attack_type
        self.attack_start = self.tick
        self.attack_duration = duration

    def stop_attack(self):
        """Stop any active attack injection."""
        self.attack_active = None

    def _apply_attack(self, metrics):
        """Modify metrics based on the currently active attack type."""
        elapsed = self.tick - self.attack_start

        if elapsed > self.attack_duration:
            self.attack_active = None
            return metrics

        progress = elapsed / self.attack_duration

        if self.attack_active == "dos":
            # DoS: massive network spike + high CPU
            intensity = 8 + 20 * progress
            metrics["network"] = self._clamp(
                metrics["network"] * intensity + self.rng.normal(0, 500), 10, 50000
            )
            metrics["cpu"] = self._clamp(
                75 + self.rng.normal(15, 5), 2, 100
            )

        elif self.attack_active == "bruteforce":
            # Brute-force: periodic CPU spikes every few seconds
            if self.tick % 3 == 0:
                metrics["cpu"] = self._clamp(
                    70 + self.rng.normal(20, 8), 2, 100
                )
            metrics["network"] = self._clamp(
                metrics["network"] * 2.5 + self.rng.normal(0, 100), 10, 50000
            )

        elif self.attack_active == "ransomware":
            # Ransomware: very high disk writes, moderate CPU
            metrics["disk_io"] = self._clamp(
                800 + self.rng.normal(400, 100) * (1 + progress), 5, 2000
            )
            metrics["cpu"] = self._clamp(
                55 + self.rng.normal(15, 5), 2, 100
            )
            metrics["network"] = self._clamp(
                metrics["network"] * 0.4, 10, 50000
            )

        elif self.attack_active == "cryptomining":
            # Cryptomining: sustained very high CPU, elevated memory
            metrics["cpu"] = self._clamp(
                90 + self.rng.normal(5, 2), 2, 100
            )
            metrics["memory"] = self._clamp(
                70 + self.rng.normal(10, 3), 20, 100
            )

        return metrics

    def generate_sample(self):
        """Generate a single timestamped metric sample."""
        self.tick += 1
        metrics = self._normal_metrics()

        if self.attack_active:
            metrics = self._apply_attack(metrics)

        return {
            "timestamp": datetime.now().isoformat(),
            "vm_id": self.vm_id,
            "tick": self.tick,
            "cpu": round(metrics["cpu"], 2),
            "memory": round(metrics["memory"], 2),
            "disk_io": round(metrics["disk_io"], 2),
            "network": round(metrics["network"], 2),
            "attack_label": self.attack_active or "normal",
        }
