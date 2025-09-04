# macOS Authorization Discovery Tool

A comprehensive tool for discovering and analyzing macOS system settings that require authentication or authorization. This tool helps security researchers, system administrators, and developers understand the authorization landscape of macOS systems.

## Features

- **Comprehensive Discovery**: Checks 15+ categories of macOS authorization points
- **Dynamic System Settings**: Automatically discovers available System Settings panes for your macOS version and hardware
- **Hardware Feature Detection**: Comprehensive hardware profiling including Touch ID, Thunderbolt, Apple Silicon detection
- **Web Dashboard**: User-friendly web interface for viewing results with real-time updates
- **Real-time Progress**: Live updates during discovery process
- **Detailed Analysis**: In-depth information about each authorization requirement
- **Version Adaptive**: Works across different macOS versions (macOS 12+ recommended)
- **Privacy-Focused**: Sanitized for public use, no sensitive data collection

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bcampbellbt/find_auth.git
   cd find_auth/macos_auth_discovery
   ```

2. **Run the tool (automatic setup):**
   ```bash
   ./run.sh
   ```
   
   The script will automatically:
   - Create a Python virtual environment
   - Install all dependencies
   - Start the web server

3. **Access the dashboard:**
   Open your browser to [http://localhost:5000](http://localhost:5000)

## What It Discovers

The tool analyzes these authorization categories:

### Security Framework
- **Gatekeeper**: App notarization and code signing verification
- **System Integrity Protection (SIP)**: System file protection
- **Secure Boot**: Boot process integrity verification
- **FileVault**: Full disk encryption status
- **Firmware Password**: Hardware-level access protection

### Privacy & Permissions
- **TCC Database**: Privacy-sensitive app permissions
- **Location Services**: GPS access controls
- **Screen Recording**: Display capture permissions
- **Full Disk Access**: Complete filesystem access
- **Accessibility Permissions**: UI automation access

### System Administration
- **Administrator Accounts**: Users with admin privileges
- **Password Policy**: System password requirements
- **Certificate Trust**: SSL/TLS certificate management
- **Keychain Access**: Secure credential storage

### Network Security
- **Application Firewall**: Network traffic filtering
- **VPN Configurations**: Virtual private network setups

### Development Tools
- **Xcode Command Line Tools**: Developer environment
- **Code Signing Identities**: App signing certificates
- **System Extensions**: Kernel and system-level extensions

## Web Dashboard

The tool provides a comprehensive web interface featuring:

- **Discovery Controls**: Start/stop discovery processes
- **Real-time Progress**: Live updates during scanning
- **Results Browser**: Detailed view of all findings
- **Hardware Profile**: Comprehensive system information and hardware feature detection
- **System Settings Discovery**: Dynamic detection of available System Settings panes with real-time statistics
- **Export Options**: Save results for further analysis

### Hardware Features Detected
- **System Model**: Mac model identification (e.g., MacBook Pro, iMac, Mac Studio)
- **Processor**: CPU architecture and brand detection (Apple Silicon vs Intel)
- **Security Features**: Touch ID, Face ID, Secure Enclave availability detection
- **Connectivity**: Thunderbolt, Wi-Fi, Bluetooth, Ethernet detection
- **Power**: Battery presence and status (laptops vs desktops)
- **Peripherals**: Display count, audio devices enumeration
- **macOS Version**: Detailed version information and build numbers

## Dynamic System Settings Discovery

The tool automatically discovers System Settings panes available on your specific macOS version and configuration:

- **Version Awareness**: Detects macOS version and uses appropriate discovery method
- **Modern Systems**: Uses System Settings extensions for macOS 13+
- **Legacy Support**: Falls back to preference panes for older macOS versions  
- **Real-time Adaptation**: Discovers actual available panes instead of using static lists
- **Hardware Integration**: Filters panes based on detected hardware capabilities
- **Comprehensive Coverage**: Typically finds 46+ panes vs static configuration of 36

### Recent Discovery Results (Example: macOS 15.x)
- **System Model**: MacBook Pro (Apple Silicon)
- **Architecture**: arm64
- **Total Panes**: 46+ discovered vs 36 static
- **New Panes Found**: Apple ID, Lock Screen, Family, Passwords, and others
- **Hardware Features**: Touch ID, Thunderbolt, Battery status detection

This ensures the tool works accurately across different macOS versions and system configurations without manual updates.

## Technical Details

### Architecture
- **Flask Web Framework**: Modern web interface
- **Python 3.13+**: Core application runtime
- **SQLite Integration**: TCC database analysis
- **Command-line Tools**: System command integration

### Discovery Methods
- System command execution (`spctl`, `csrutil`, `fdesetup`, etc.)
- Database queries (TCC.db privacy permissions)
- File system inspection (preference panes, applications)
- Hardware profiling (security chips, architecture, Touch ID, etc.)
- Dynamic System Settings extension enumeration
- Real-time pane availability validation

### Permissions Required
- **Standard User**: Most discovery functions work without elevation
- **Admin Privileges**: Required for some security checks (firmware password)
- **Accessibility**: Needed for UI automation (if using automation features)

## Requirements

- **macOS 10.15+ (Catalina or later)** - Required for modern System Settings support
- **Python 3.8+** - Will be checked automatically by setup script
- **Admin Privileges** - Required for some advanced security checks (optional)
- **Terminal Access** - For running command-line tools and system analysis

### System Permissions (Automatic Setup)
The tool will guide you through granting necessary permissions:
- **Full Disk Access** - For comprehensive system analysis
- **Developer Tools** - For security framework access
- **Privacy Settings** - For TCC database analysis

## Installation

### One-Command Setup (Recommended)
```bash
# Clone and run in one command
git clone https://github.com/bcampbellbt/find_auth.git && cd find_auth/macos_auth_discovery && ./run.sh
```

### Step-by-Step Installation
If you prefer manual setup or encounter issues:

```bash
# 1. Clone the repository
git clone https://github.com/bcampbellbt/find_auth.git
cd find_auth/macos_auth_discovery

# 2. Ensure Python 3.8+ is installed
python3 --version

# 3. Create virtual environment
python3 -m venv venv

# 4. Activate virtual environment
source venv/bin/activate

# 5. Install dependencies
pip install -r requirements.txt

# 6. Run the application
python3 app.py
```

## Usage

### Web Interface (Recommended)
1. Start the server: `./run.sh`
2. Open browser to: `http://localhost:5000`
3. Click "Start Discovery" to begin scanning
4. View results in real-time as they populate

### Command Line
The web interface provides the most comprehensive experience, but you can also interact with the discovery engine programmatically.

## Project Structure

```
macos_auth_discovery/
├── app.py                 # Main Flask application entry point
├── run.sh                # Simple launcher script
├── requirements.txt      # Python dependencies
├── src/
│   ├── core/
│   │   ├── command_discovery.py    # Main discovery engine
│   │   ├── pane_discovery.py       # Dynamic System Settings discovery
│   │   ├── hardware_profile.py     # Hardware feature detection
│   │   └── system_monitor.py       # System-level monitoring
│   └── web/
│       ├── app.py                   # Flask web application
│       └── templates/
│           └── dashboard.html       # Web interface
├── docs/                 # Technical documentation
│   ├── DYNAMIC_PANE_DISCOVERY.md
│   ├── PROJECT_OVERVIEW.md
│   └── TECHNICAL_SPEC.md
├── README.md
└── LICENSE
```

## Development

### Adding New Discovery Categories
1. Add new check method to `CommandDiscoveryEngine` class
2. Include in `discover_all_authorizations()` method list
3. Update `total_checks` counter (automatically adjusted for dynamic panes)
4. Test with various macOS configurations and hardware types

### Adding Hardware Feature Detection
1. Extend `HardwareProfileManager` class with new detection methods
2. Update `_detect_hardware()` method to include new features
3. Add feature validation in `_check_pane_availability()`
4. Test across different Mac models and configurations

### Customizing Web Interface
- Templates in `src/web/templates/`
- Static files can be added to `src/web/static/`
- API endpoints in `src/web/app.py`

## Security Considerations

- Tool runs with minimal privileges by default
- No sensitive data is collected or transmitted
- All analysis is performed locally
- Results contain system configuration, not user data

## Compatibility

### Tested macOS Versions
- macOS 15.x (Sequoia) ✅
- macOS 14.x (Sonoma) ✅  
- macOS 13.x (Ventura) ✅
- macOS 12.x (Monterey) ✅

### Hardware Compatibility
- Apple Silicon (M1/M2/M3) ✅
- Intel-based Macs ✅
- T2 Security Chip detection ✅

## Troubleshooting

**Permission Denied Errors**
```bash
# Grant Full Disk Access to Terminal.app in:
# System Settings > Privacy & Security > Full Disk Access
```

**Web Server Won't Start**
```bash
# Check if port 5000 is available
lsof -i :5000

# Use different port if needed
export FLASK_RUN_PORT=8080
python3 app.py
```

**Discovery Finds Few Results**
- Ensure Terminal.app has necessary permissions
- Run with admin privileges: `sudo ./run.sh`
- Check System Settings > Privacy & Security permissions

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Test on multiple macOS versions
4. Submit pull request with detailed description

## License

MIT License - see LICENSE file for details.