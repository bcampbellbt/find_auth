# macOS System Settings Authorization Discovery

An open-source tool for automated discovery and analysis of authorization requirements within macOS systems. This tool helps security professionals, system administrators, and researchers understand the complete authorization landscape of macOS systems through system commands and file analysis.

## Features

- **System-Level Discovery**: Uses native macOS commands and system files to discover authorization points
- **Dynamic System Settings Discovery**: Automatically discovers available System Settings panes based on macOS version and hardware
- **Comprehensive Hardware Profiling**: Detects system capabilities, security features, and hardware-dependent settings
- **Authorization Detection**: Identifies points where user authorization is required without UI automation
- **Real-time Monitoring**: Web dashboard for live progress tracking and results
- **Multiple Export Formats**: JSON, CSV, and PDF report generation
- **Non-Invasive**: Uses system commands and file inspection instead of UI automation
- **Security-Focused**: Safe, read-only exploration that respects system boundaries
- **Version Adaptive**: Works across different macOS versions with automatic adaptation

## Use Cases

- Security testing and vulnerability assessment
- System administration and compliance auditing
- Academic research on macOS authorization mechanisms
- Documentation of system permission requirements
- Baseline creation for system hardening

## Discovery Methods

### 1. System Commands
- `defaults read` for system and user preferences
- `system_profiler` for hardware and software configuration
- `networksetup` for network-related permissions
- `security` framework commands for security settings

### 2. File Analysis
- TCC database inspection for privacy permissions
- Property list (.plist) file analysis
- System configuration files examination
- Authorization database review

### 3. Hardware Profiling
- Mac model identification and classification
- Apple Silicon vs Intel architecture detection
- Security feature availability (Touch ID, Face ID, Secure Enclave)
- Connectivity capabilities (Thunderbolt, Wi-Fi, Bluetooth)
- Display and audio device enumeration
- Battery and power management status

### 4. Dynamic System Settings Discovery
- Real-time System Settings pane enumeration
- macOS version-aware discovery methods
- Hardware-dependent pane filtering
- Extension-based discovery for modern macOS versions

## Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd macos_auth_discovery
   ```

2. **Run setup**
   ```bash
   ./setup.sh
   ```

3. **Configure permissions** (see README.md for detailed instructions)

4. **Start discovery**
   ```bash
   python main.py --mode both --debug
   ```

## Documentation

- [README.md](README.md) - Detailed setup and usage instructions
- [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) - Technical architecture and specifications
- [LICENSE](LICENSE) - License terms and security notice

## Requirements

- macOS 13.0+ (Ventura, Sonoma, or Sequoia)
- Python 3.8+
- Administrator access for some system commands

## Contributing

Contributions are welcome! Please read the contributing guidelines in README.md and ensure all changes include appropriate tests.

## Security

This tool is designed for legitimate security testing and research purposes. Please use responsibly and only on systems you have authorization to test.

## License

MIT License - see [LICENSE](LICENSE) for details.
