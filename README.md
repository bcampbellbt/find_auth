# macOS Authorization Discovery Tool

A comprehensive tool for discovering and analyzing macOS system settings that require authentication or authorization. This tool helps security researchers, system administrators, and developers understand the authorization landscape of macOS systems.

## Features

- **Comprehensive Discovery**: Checks 15+ categories of macOS authorization points
- **Web Dashboard**: User-friendly web interface for viewing results
- **Real-time Progress**: Live updates during discovery process
- **Detailed Analysis**: In-depth information about each authorization requirement
- **Privacy-Focused**: Sanitized for public use, no sensitive data collection

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd find_auth/macos_auth_discovery
   ```

2. **Run the tool:**
   ```bash
   ./run.sh
   ```

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
- **Hardware Profile**: System information display
- **Export Options**: Save results for further analysis

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
- Hardware profiling (security chips, architecture)

### Permissions Required
- **Standard User**: Most discovery functions work without elevation
- **Admin Privileges**: Required for some security checks (firmware password)
- **Accessibility**: Needed for UI automation (if using automation features)

## Requirements

- macOS 10.15+ (Catalina or later)
- Python 3.8+
- Administrative access (for some features)

## Installation

### Automatic Setup
The `run.sh` script handles all setup automatically:
```bash
./run.sh
```

### Manual Setup
If you prefer manual installation:
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
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
│   │   └── command_discovery.py    # Discovery engine
│   └── web/
│       ├── app.py                   # Flask web application
│       └── templates/
│           └── dashboard.html       # Web interface
├── README.md
└── LICENSE
```

## Development

### Adding New Discovery Categories
1. Add new check method to `CommandDiscoveryEngine` class
2. Include in `discover_all_authorizations()` method list
3. Update `total_checks` counter
4. Test with various macOS configurations

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

### Common Issues

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

## Acknowledgments

- Built for macOS security research community
- Inspired by need for comprehensive authorization visibility
- Designed with privacy and security best practices
