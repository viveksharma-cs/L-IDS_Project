import subprocess
import re
import time
import logging

class VBoxCollector:
    """
    Agentless collector that fetches metrics from an Oracle VM VirtualBox 
    Guest using the VBoxManage tool on the Windows host.
    """
    def __init__(self, vm_name, vbox_path=r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"):
        self.vm_name = vm_name
        self.vbox_path = vbox_path
        self.metrics_setup_done = False
        
        # Mapping L-IDS metrics to VirtualBox Object/Metric strings
        self.metric_map = {
            'cpu': 'CPU/Load/User',
            'memory': 'RAM/Usage/Used',
            'network_rx': 'Net/Rate/Rx',
            'network_tx': 'Net/Rate/Tx'
        }

    def _run_vbox_cmd(self, args):
        """Helper to run VBoxManage commands."""
        try:
            cmd = [self.vbox_path] + args
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                logging.warning(f"VBoxManage command failed: {' '.join(cmd)} - {result.stderr}")
            return result.stdout
        except Exception as e:
            logging.error(f"Error executing VBoxManage: {str(e)}")
            return ""

    def setup_metrics(self):
        """Enable metrics collection for the target VM."""
        logging.info(f"Setting up VirtualBox metrics for VM: {self.vm_name}")
        metrics_list = ",".join(self.metric_map.values())
        
        # Setup period=1s, samples=1
        self._run_vbox_cmd(["metrics", "setup", "--period", "1", "--samples", "1", self.vm_name, metrics_list])
        self.metrics_setup_done = True

    def query_metrics(self):
        """
        Query current metrics from VBoxManage.
        Returns a dictionary formatted for the L-IDS Preprocessor.
        """
        if not self.metrics_setup_done:
            self.setup_metrics()

        output = self._run_vbox_cmd(["metrics", "query", self.vm_name])
        
        # Default fallback values
        data = {
            'cpu': 0.0,
            'memory': 0.0,
            'disk_io': 0.0, # Disk is harder to get via general VBox metrics (using placeholder)
            'network': 0.0,
            'attack_label': 'normal'
        }

        if not output:
            return data

        # Regex parsing for percentage (CPU) or numbers (Network)
        # VirtualBox output example: "deta       CPU/Load/User     12.50%"
        try:
            # Parse CPU
            cpu_match = re.search(r"CPU/Load/User\s+([\d.]+)", output)
            if cpu_match:
                data['cpu'] = float(cpu_match.group(1))

            # Parse RAM (Used memory usually in MB or KB)
            # VBox stats for RAM can be "RAM/Usage/Used"
            ram_match = re.search(r"RAM/Usage/Used\s+([\d.]+)\s+(\w+)", output)
            if ram_match:
                val = float(ram_match.group(1))
                unit = ram_match.group(2).lower()
                # Normalize RAM usage (VBox reports absolute MB, we simulate % based on typical 4GB Kali VM)
                kili_total_ram = 4096.0 # Assume 4GB
                if 'kb' in unit: val /= 1024
                data['memory'] = (val / kili_total_ram) * 100

            # Parse Network (Rate in bytes/s)
            rx_match = re.search(r"Net/Rate/Rx\s+([\d.]+)", output)
            tx_match = re.search(r"Net/Rate/Tx\s+([\d.]+)", output)
            if rx_match and tx_match:
                data['network'] = float(rx_match.group(1)) + float(tx_match.group(1))

            # Disk I/O: VirtualBox doesn't provide a guest-normalized Disk I/O metric easily via query.
            # We'll use a small constant or derivative if needed, but for now we'll keep at 0 
            # or simulate based on RAM activity.
            data['disk_io'] = data['memory'] * 0.1 # Very rough proxy for demonstration

        except Exception as e:
            logging.error(f"Error parsing metrics output: {str(e)}")

        return data

if __name__ == "__main__":
    # Test script
    logging.basicConfig(level=logging.INFO)
    collector = VBoxCollector("deta")
    while True:
        stats = collector.query_metrics()
        print(f"Captured: {stats}")
        time.sleep(2)
