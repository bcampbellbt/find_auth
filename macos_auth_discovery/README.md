# macOS Authorization Discovery Tool

A comprehensive tool for discovering and analyzing macOS system settings that require authentication or authorization. Perfect for security teams, system administrators, and compliance auditing.

## 🚀 Quick Start for Teams

### One-Command Setup
```bash
git clone https://github.com/bcampbellbt/find_auth.git
cd find_auth/macos_auth_discovery
./run.sh
```

Open [http://localhost:5000](http://localhost:5000) in your browser and click "Start Discovery"

### What You'll Need
- **macOS 10.15+** (Catalina or later)
- **Python 3.8+** (checked automatically)
- **5 minutes** for initial setup
- **Terminal access** with Full Disk Access (optional, but recommended)

## 🎯 What This Tool Does

### Comprehensive Authorization Discovery
- **46+ System Settings Panes** - Dynamically discovered based on your macOS version
- **15+ Security Categories** - From Gatekeeper to FileVault to TCC permissions
- **Hardware Feature Detection** - Touch ID, Thunderbolt, Apple Silicon, etc.
- **Real-time Analysis** - Live web dashboard with progress tracking

### Perfect for Security Teams
- **Security Testing** - Comprehensive authorization mapping for penetration testing
- **Compliance Auditing** - Document all system permission requirements
- **Baseline Creation** - Establish security baselines across different Mac configurations
- **Change Detection** - Track authorization modifications across system updates

## 📊 Web Dashboard Features

- **Real-time Discovery** - Watch authorization points being discovered live
- **Hardware Profile** - Complete system information and capability detection
- **Results Browser** - Detailed view of all discovered authorization requirements
- **Export Options** - Save results for reports and further analysis
- **Progress Tracking** - See exactly what's being analyzed in real-time

## 🔧 Setup for Team Deployment

### Individual Setup
Each team member runs:
```bash
./run.sh
```

### Batch Deployment
For setting up multiple machines:
```bash
# Clone to shared location
git clone https://github.com/bcampbellbt/find_auth.git /shared/tools/find_auth

# Each user runs:
cd /shared/tools/find_auth/macos_auth_discovery
./run.sh
```

### Permissions Setup
For full functionality, grant Terminal.app "Full Disk Access":
1. System Settings > Privacy & Security > Full Disk Access
2. Add Terminal.app (or your preferred terminal)
3. Restart the tool

## 🛠 Troubleshooting

### Common Issues
```bash
# Check system compatibility
python3 setup_check.py

# Verify Python version
python3 --version

# Manual dependency install
pip install -r requirements.txt

# Reset virtual environment
rm -rf venv && ./run.sh
```

### Permission Issues
- **TCC Database Access**: Requires Full Disk Access for comprehensive privacy analysis
- **Security Framework**: Some features need admin privileges
- **System Files**: Modern macOS protects system files - Full Disk Access recommended

## 📁 Project Structure

```
macos_auth_discovery/
├── run.sh                 # One-command setup and launch
├── setup_check.py         # System compatibility verification
├── app.py                 # Main application entry point
├── requirements.txt       # Python dependencies
├── src/core/              # Core discovery engines
├── src/web/               # Web dashboard
├── docs/                  # Technical documentation
└── README.md             # This file
```

## 🧪 Discovery Results Example

**Typical Discovery Results:**
- **194 Authorization Points** across 46 System Settings panes
- **Hardware Features**: Touch ID, Thunderbolt, Battery, Display config
- **Security Framework**: Gatekeeper, SIP, FileVault, Secure Boot
- **Privacy Permissions**: TCC database, Location Services, Screen Recording
- **System Admin**: User accounts, Keychain, Certificate trust

## 🔒 Security & Privacy

- **Read-Only Analysis** - No system modifications made
- **Local Processing** - All analysis performed locally
- **No Data Collection** - No sensitive information transmitted
- **Safe Operation** - Respects system boundaries and permissions

## 📚 Documentation

- **[Dynamic Pane Discovery](docs/DYNAMIC_PANE_DISCOVERY.md)** - How the tool adapts to different macOS versions
- **[Project Overview](docs/PROJECT_OVERVIEW.md)** - Comprehensive feature documentation
- **[Technical Specification](docs/TECHNICAL_SPEC.md)** - Architecture and implementation details

## 🤝 Team Collaboration

### Sharing Results
- Export discovery results as JSON for team analysis
- Compare baselines across different Mac configurations
- Document authorization requirements for compliance

### Use Cases
- **Security Assessments** - Comprehensive authorization mapping
- **Compliance Audits** - Document all system permission requirements  
- **System Hardening** - Identify and baseline security configurations
- **Change Management** - Track authorization changes across updates

## 📞 Support

### Quick Help
```bash
# System compatibility check
python3 setup_check.py

# View logs for troubleshooting
tail -f auth_discovery.log
```

### Common Team Questions
- **Multi-user setup**: Each user runs their own instance
- **Results sharing**: Export JSON files for team analysis
- **Permission requirements**: Full Disk Access recommended but not required
- **macOS versions**: Tested on macOS 12+ (Monterey through Sequoia)

---

**Ready to discover your Mac's authorization landscape?**
```bash
./run.sh
```
