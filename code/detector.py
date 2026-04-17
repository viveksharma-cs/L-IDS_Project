"""
detector.py — Core anomaly detection engine for L-IDS.

Implements dual-mechanism detection:
  1. Static threshold detection using mean + k*sigma boundaries
  2. Exponential Moving Average (EMA) adaptive baselines

Produces a composite anomaly score across all four resource dimensions.
"""

import numpy as np
from collections import deque


class AnomalyDetector:
    """Statistical anomaly detection engine with EMA baselines and threshold scoring."""

    METRIC_KEYS = ["cpu", "memory", "disk_io", "network"]

    def __init__(self, k_warning=2.5, k_critical=4.5, ema_alpha=0.1,
                 calibration_window=60, persistence_threshold=3):
        """
        Args:
            k_warning: Sigma multiplier for warning-level alerts (2.5 for stability).
            k_critical: Sigma multiplier for critical-level alerts (4.5 for high precision).
            ema_alpha: Smoothing factor for EMA (0 < alpha <= 1).
            calibration_window: Samples for initial baseline (60 for stability).
            persistence_threshold: Consecutive samples required for CRITICAL alert.
        """
        self.k_warning = k_warning
        self.k_critical = k_critical
        self.ema_alpha = ema_alpha
        self.calibration_window = calibration_window
        self.persistence_threshold = persistence_threshold

        # Persistence tracking
        self.consecutive_anomalies = 0
        self.last_severity = "normal"

        # Metric weights for composite score
        self.weights = {
            "cpu": 0.30,
            "memory": 0.20,
            "disk_io": 0.20,
            "network": 0.30,
        }

        # Baseline storage
        self.baselines = {}
        self.ema = {}
        self.calibration_data = {key: [] for key in self.METRIC_KEYS}
        self.calibrated = False
        self.sample_count = 0

        # Alert history
        self.alert_log = deque(maxlen=500)
        self.score_history = deque(maxlen=300)

        # Detection counters
        self.stats = {
            "total_samples": 0,
            "total_alerts": 0,
            "info_alerts": 0,
            "warning_alerts": 0,
            "critical_alerts": 0,
            "normal_count": 0,
        }

    def _calibrate(self):
        """Compute baseline mean and std from calibration data."""
        for key in self.METRIC_KEYS:
            data = np.array(self.calibration_data[key])
            self.baselines[key] = {
                "mean": float(np.mean(data)),
                "std": float(max(np.std(data), 0.01)),  # Prevent zero std
            }
            self.ema[key] = float(np.mean(data))
        self.calibrated = True

    def _update_ema(self, key, value):
        """Update the exponential moving average for a metric."""
        if key in self.ema:
            self.ema[key] = (
                self.ema_alpha * value + (1 - self.ema_alpha) * self.ema[key]
            )
        else:
            self.ema[key] = value

    def _compute_metric_score(self, key, value):
        """
        Compute an anomaly score for a single metric.
        Returns a value >= 0 indicating how many standard deviations
        the value is above the baseline.
        """
        baseline = self.baselines[key]
        ema_val = self.ema[key]

        # Distance from baseline in sigma units
        baseline_deviation = abs(value - baseline["mean"]) / baseline["std"]

        # Distance from EMA in sigma units
        ema_deviation = abs(value - ema_val) / baseline["std"]

        # Take the average of both for a balanced score
        # This gives weight to both the long-term baseline and recent trend
        score = 0.6 * baseline_deviation + 0.4 * ema_deviation

        return round(score, 3)

    def analyze(self, normalized_sample, raw_sample, features=None):
        """
        Analyze a single sample and return detection results.

        Args:
            normalized_sample: Dict with normalized metric values (0-1 range).
            raw_sample: Original raw metric values for display.
            features: Optional windowed features from preprocessor.

        Returns:
            Dict with anomaly scores, alert level, and details.
        """
        self.sample_count += 1
        self.stats["total_samples"] += 1

        # Phase 1: Calibration
        if not self.calibrated:
            for key in self.METRIC_KEYS:
                self.calibration_data[key].append(normalized_sample[key])
            if self.sample_count >= self.calibration_window:
                self._calibrate()
            return {
                "status": "calibrating",
                "progress": self.sample_count / self.calibration_window,
                "remaining": self.calibration_window - self.sample_count,
            }

        # Phase 2: Detection
        metric_scores = {}
        metric_details = {}

        for key in self.METRIC_KEYS:
            value = normalized_sample[key]
            self._update_ema(key, value)
            score = self._compute_metric_score(key, value)
            metric_scores[key] = score
            metric_details[key] = {
                "value": round(value, 4),
                "raw_value": raw_sample[key],
                "ema": round(self.ema[key], 4),
                "baseline_mean": round(self.baselines[key]["mean"], 4),
                "baseline_std": round(self.baselines[key]["std"], 4),
                "score": score,
            }

        # Composite anomaly score (weighted sum)
        composite = sum(
            self.weights[key] * metric_scores[key] for key in self.METRIC_KEYS
        )
        composite = round(composite, 3)

        # -- IMPROVED SEVERITY LOGIC (PERFECT DETECTION) --
        severity = "normal"
        raw_severity = "normal"

        # 1. Determine "Raw" severity based on thresholds
        if composite >= self.k_critical:
            raw_severity = "critical"
        elif composite >= self.k_warning:
            raw_severity = "warning"
        elif composite >= self.k_warning * 0.7:
            raw_severity = "info"

        # 2. Apply Persistence Logic (Debouncing transient spikes like Firefox)
        if raw_severity == "critical":
            self.consecutive_anomalies += 1
            # Only escalate to CRITICAL if it persists (e.g., 3 seconds)
            if self.consecutive_anomalies >= self.persistence_threshold:
                severity = "critical"
            else:
                # If it's a new spike, keep it as WARNING for now
                severity = "warning" 
        elif raw_severity == "warning":
            self.consecutive_anomalies = 0 # Reset but keep warning
            severity = "warning"
        else:
            self.consecutive_anomalies = 0
            severity = raw_severity

        # 3. Update Statistics
        if severity == "critical":
            self.stats["critical_alerts"] += 1
            self.stats["total_alerts"] += 1
        elif severity == "warning":
            self.stats["warning_alerts"] += 1
            self.stats["total_alerts"] += 1
        elif severity == "info":
            self.stats["info_alerts"] += 1
            self.stats["total_alerts"] += 1
        else:
            self.stats["normal_count"] += 1

        # Identify which metrics are contributing most
        contributing = sorted(
            metric_scores.items(), key=lambda x: x[1], reverse=True
        )
        top_contributor = contributing[0][0] if contributing else "none"

        # Generate alert description
        description = self._generate_description(severity, top_contributor, metric_scores, features)

        # Build result
        result = {
            "status": "detecting",
            "timestamp": raw_sample.get("timestamp", ""),
            "vm_id": raw_sample.get("vm_id", "unknown"),
            "composite_score": composite,
            "severity": severity,
            "description": description,
            "metric_scores": metric_scores,
            "metric_details": metric_details,
            "top_contributor": top_contributor,
            "attack_label": raw_sample.get("attack_label", "unknown"),
        }

        # Log alerts
        if severity != "normal":
            self.alert_log.append(result.copy())

        self.score_history.append(composite)

        return result

    def _generate_description(self, severity, top_metric, scores, features):
        """Generate a human-readable description for the detected anomaly."""
        if severity == "normal":
            return "All metrics within expected boundaries."

        descriptions = {
            "cpu": "CPU utilization significantly elevated",
            "memory": "Memory consumption abnormally high",
            "disk_io": "Disk I/O activity showing unusual patterns",
            "network": "Network traffic volume abnormally elevated",
        }

        base = descriptions.get(top_metric, "Unusual activity detected")

        # Add cross-correlation insights (The "Perfect" Check)
        if features and severity in ("warning", "critical"):
            cpu_score = scores.get("cpu", 0)
            net_score = scores.get("network", 0)
            disk_score = scores.get("disk_io", 0)
            
            # Attack Signatures
            if cpu_score > 3.0 and net_score > 3.0:
                return f"[ATTACK] Corelation between CPU and Network detected. Potential DDoS/Flood incoming."
            elif disk_score > 3.0 and net_score < 1.0:
                return f"[ATTACK] Massive Disk Write with low Network activity. Potential Ransomware/Encryption."
            elif cpu_score > 4.0 and severity == "critical":
                 return f"[RESOURCE ABUSE] Sustained High CPU detected. Potential Cryptomining or Malicious Process."
            elif cpu_score > 2.5 and severity == "warning" and self.consecutive_anomalies < self.persistence_threshold:
                 return f"[TRANSIENT] Detected high CPU burst (Firefox/App Start). System is monitoring for persistence."

        severity_label = severity.upper()
        return f"[{severity_label}] {base} (score: {scores[top_metric]:.1f}σ)."

    def get_stats(self):
        """Return current detection statistics."""
        total = self.stats["total_samples"]
        alerts = self.stats["total_alerts"]
        return {
            **self.stats,
            "alert_rate": round(alerts / max(total, 1) * 100, 2),
            "calibrated": self.calibrated,
            "recent_scores": list(self.score_history)[-30:],
        }

    def get_recent_alerts(self, count=20):
        """Return the most recent alerts."""
        return list(self.alert_log)[-count:]

    def get_baselines(self):
        """Return the computed baselines for display."""
        if not self.calibrated:
            return None
        return {
            key: {
                "mean": round(self.baselines[key]["mean"], 4),
                "std": round(self.baselines[key]["std"], 4),
                "ema": round(self.ema.get(key, 0), 4),
            }
            for key in self.METRIC_KEYS
        }
