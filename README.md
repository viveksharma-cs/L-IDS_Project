# L-IDS: Lightweight Intrusion Detection for Cloud VMs
**Minor Project — Session 2024-25**

This project implements an agentless, VMM-level intrusion detection system (IDS) that uses statistical anomaly detection to identify threats in cloud virtual machines with minimal resource overhead.

## Project Structure

- `research_paper/`: Contains the final 10-page research paper PDF and visual explainer.
- `code/`: Contains the fully functional Python prototype.
  - `main.py`: Flask web application with Mode Switching.
  - `collector_vbox.py`: Real-time Oracle VM (VirtualBox) metric acquisition.
  - `data_generator.py`: Simulated VM metric collection and attack injection.
  - `preprocessor.py`: Normalization and feature engineering logic.
  - `detector.py`: Statistical detection engine (EMA + Thresholds).
  - `requirements.txt`: Python dependencies.
  - `templates/`: Real-time HTML dashboard.

## How to Run the Project

### 1. Prerequisites
- Python 3.8+ installed.
- Oracle VM VirtualBox (if using Real-Mode).

### 2. Choose Your Mode

#### Option A: Simulation Mode (Testing Attacks)
Best for demonstrating how the system detects DoS, Ransomware, etc.
```bash
python main.py --mode sim
```

#### Option B: Real-Time Mode (Monitoring your Kali Linux)
Best for showing how the system monitors actual VM performance.
1. Run this once on your host (Windows):
   `& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" metrics setup --period 1 --samples 1 "deta"`
2. Start your Kali VM.
3. Run the IDS:
   `python main.py --mode real --vm deta`

### 3. Access the Interface
Open your web browser and navigate to:
**http://127.0.0.1:5000**

## Project Documentation
Check the `research_paper/` folder for the following PDFs:
- `Research_Paper.pdf`: The complete 10-page academic report.
- `Project_Explainer_Visual_Guide.pdf`: Analogies and visuals for your presentation.
- `Project_Final_Walkthrough.pdf`: Technical details of the implementation.

## Authors
- Vivek Sharma
- Ritika Kalra
- Rudra Mohan
- Lakshya Raj
- Mohammad Anas

**Supervisor:** Dr. Sandeep Saxena
**School:** Computer Science and Engineering, IILM University
