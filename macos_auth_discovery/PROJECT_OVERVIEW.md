# macOS System Settings Authorization Discovery

An open-source tool for automated discovery and analysis of authorization requirements within macOS System Settings. This tool helps security professionals, system administrators, and researchers understand the complete authorization landscape of macOS systems.

## Features

- **Comprehensive Discovery**: Automatically explores all accessible System Settings panes
- **Authorization Detection**: Identifies points where user authorization is required
- **Real-time Monitoring**: Web dashboard for live progress tracking and results
- **Multiple Export Formats**: JSON, CSV, and PDF report generation
- **Hardware-Aware**: Adapts discovery based on system capabilities
- **Security-Focused**: Non-invasive exploration with respect for system boundaries

## Use Cases

- Security testing and vulnerability assessment
- System administration and compliance auditing
- Academic research on macOS authorization mechanisms
- Documentation of system permission requirements
- Baseline creation for system hardening

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
- Accessibility permissions for UI automation

## Contributing

Contributions are welcome! Please read the contributing guidelines in README.md and ensure all changes include appropriate tests.

## Security

This tool is designed for legitimate security testing and research purposes. Please use responsibly and only on systems you have authorization to test.

## License

MIT License - see [LICENSE](LICENSE) for details.
