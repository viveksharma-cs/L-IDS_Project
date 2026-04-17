"""
preprocessor.py — Data preprocessing pipeline for L-IDS.

Handles min-max normalization of raw metrics, sliding window management,
and feature engineering (mean, std, rate of change, cross-correlation).
"""

import numpy as np
from collections import deque


class MetricsPreprocessor:
    """Normalizes raw VM metrics and computes windowed statistical features."""

    METRIC_KEYS = ["cpu", "memory", "disk_io", "network"]

    # Expected min/max ranges for normalization
    RANGES = {
        "cpu": (0.0, 100.0),
        "memory": (0.0, 100.0),
        "disk_io": (0.0, 2000.0),
        "network": (0.0, 50000.0),
    }

    def __init__(self, window_size=60):
        """
        Args:
            window_size: Number of samples in each sliding window.
        """
        self.window_size = window_size
        self.windows = {key: deque(maxlen=window_size) for key in self.METRIC_KEYS}
        self.raw_history = {key: deque(maxlen=window_size) for key in self.METRIC_KEYS}

    def normalize(self, sample):
        """Apply min-max normalization to a single sample."""
        normalized = {}
        for key in self.METRIC_KEYS:
            vmin, vmax = self.RANGES[key]
            raw = sample[key]
            if vmax - vmin == 0:
                normalized[key] = 0.0
            else:
                normalized[key] = max(0.0, min(1.0, (raw - vmin) / (vmax - vmin)))
        return normalized

    def add_sample(self, sample):
        """Add a raw sample to the sliding window and return normalized value."""
        normalized = self.normalize(sample)
        for key in self.METRIC_KEYS:
            self.windows[key].append(normalized[key])
            self.raw_history[key].append(sample[key])
        return normalized

    def is_window_ready(self):
        """Check if we have enough samples to compute window features."""
        return len(self.windows["cpu"]) >= 10  # Minimum 10 samples needed

    def compute_features(self):
        """Compute statistical features from the current sliding window."""
        if not self.is_window_ready():
            return None

        features = {}
        values = {}

        for key in self.METRIC_KEYS:
            arr = np.array(self.windows[key])
            values[key] = arr

            features[f"{key}_mean"] = float(np.mean(arr))
            features[f"{key}_std"] = float(np.std(arr))
            features[f"{key}_min"] = float(np.min(arr))
            features[f"{key}_max"] = float(np.max(arr))

            # Rate of change (first derivative approximation)
            if len(arr) >= 2:
                deltas = np.diff(arr)
                features[f"{key}_rate_of_change"] = float(np.mean(np.abs(deltas)))
            else:
                features[f"{key}_rate_of_change"] = 0.0

        # Cross-metric correlations
        if len(values["cpu"]) >= 10:
            try:
                features["corr_cpu_network"] = float(
                    np.corrcoef(values["cpu"], values["network"])[0, 1]
                )
            except:
                features["corr_cpu_network"] = 0.0

            try:
                features["corr_cpu_disk"] = float(
                    np.corrcoef(values["cpu"], values["disk_io"])[0, 1]
                )
            except:
                features["corr_cpu_disk"] = 0.0
        else:
            features["corr_cpu_network"] = 0.0
            features["corr_cpu_disk"] = 0.0

        return features

    def get_raw_stats(self):
        """Get raw (un-normalized) statistics for display purposes."""
        stats = {}
        for key in self.METRIC_KEYS:
            arr = np.array(self.raw_history[key])
            if len(arr) > 0:
                stats[key] = {
                    "mean": round(float(np.mean(arr)), 2),
                    "std": round(float(np.std(arr)), 2),
                    "current": round(float(arr[-1]), 2),
                }
            else:
                stats[key] = {"mean": 0, "std": 0, "current": 0}
        return stats
