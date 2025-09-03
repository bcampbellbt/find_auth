# macOS System Settings Authorization Discovery Tool

A comprehensive tool for discovering and cataloging authorization requests within macOS System Settings, specifically designed to enhance BeyondTrust EPM testing coverage.

## 🎯 Overview

This tool systematically navigates through every accessible option in macOS System Settings, detects authorization requests, and provides detailed reporting through a modern web dashboard. It's designed to ensure complete coverage of all authorization points that might affect endpoint protection management.

## ✨ Features

### 🔍 **Comprehensive Discovery**
- Automatically navigates through all System Settings panes
- Explores sub-menus and nested configuration options
- Detects both system-level and UI-triggered authorization requests
- Hardware-aware navigation with proper handling of unavailable options

### 🛡️ **Advanced Authorization Detection**
- **Primary Method**: System-level monitoring using Security.framework APIs
- **Fallback Method**: UI automation when system-level detection is insufficient
- Captures authorization right names, descriptions, and metadata
- Monitors TCC (Privacy) framework events
- Tracks system policy changes and kernel extension authorizations

### 🌐 **Modern Web Dashboard**
- Real-time progress monitoring during discovery
- Interactive authorization matrix visualization
- Hardware profile display and analysis
- Multiple export formats (JSON, CSV, PDF)
- Version comparison capabilities

### 🔧 **EPM-Specific Features**
- Identifies authorization points relevant to endpoint protection
- Captures privacy-related authorization requests
- Monitors kernel extension and system extension authorization points
- Tracks security policy modification requirements

## 🖥️ System Requirements

- **macOS**: 13.0 (Ventura) or later, 14.0 (Sonoma), 15.0 (Sequoia)
- **Architecture**: Intel (x64) or Apple Silicon (ARM64)
- **Python**: 3.8 or later
- **Memory**: 512MB RAM minimum
- **Storage**: 100MB free space

## 🚀 Quick Start

### 1. Clone and Setup

```bash
cd /Users/bcampbell/find_auth/macos_auth_discovery
./setup.sh
```

### 2. Grant Permissions

Before running the tool, you need to grant several permissions in **System Preferences > Privacy & Security**:

- **Accessibility**: Required for UI automation
- **Developer Tools**: Required for terminal access to system logs
- **Full Disk Access**: Optional, but improves authorization detection

### 3. Run the Application

```bash
# Full application (discovery + web dashboard)
./run.sh

# Web dashboard only
./run_web.sh

# Discovery only (command line)
./run_discovery.sh
```

### 4. Access Web Dashboard

Open your browser and navigate to: **http://localhost:5000**

## 📖 Usage Guide

### Starting Discovery

1. **Web Interface**:
   - Open the web dashboard at http://localhost:5000
   - Click "Start Discovery" on the main dashboard
   - Monitor progress in real-time

2. **Command Line**:
   ```bash
   python main.py --mode discover
   ```

### Monitoring Progress

The web dashboard provides real-time updates including:
- **Progress percentage** and current System Settings pane
- **Authorization count** and unique rights discovered
- **Recent events** and system status
- **Hardware compatibility** information

### Viewing Results

Results are available in multiple formats:
- **Web Dashboard**: Interactive tables and visualizations
- **JSON Export**: Complete raw data for programmatic analysis
- **CSV Export**: Tabular data for spreadsheet analysis
- **Saved Reports**: Automatic report generation in `data/` directory

## 🏗️ Architecture

### Core Components

```
macos_auth_discovery/
├── src/
│   ├── core/
│   │   ├── discovery_engine.py     # Main discovery orchestration
│   │   ├── system_monitor.py       # System-level authorization monitoring
│   │   └── hardware_profile.py     # Hardware detection and classification
│   └── web/
│       ├── app.py                  # Flask web application
│       └── templates/
│           └── dashboard.html      # Web dashboard UI
├── data/                           # Discovery reports and exports
├── logs/                           # Application logs
├── main.py                         # Application entry point
└── setup.sh                       # Setup and installation script
```

### Detection Strategy

1. **System-Level Monitoring** (Primary)
   - Monitors `authd`, `SecurityAgent`, and `tccd` processes
   - Uses Security.framework APIs where available
   - Captures authorization database changes

2. **UI Automation** (Fallback)
   - Uses AppleScript and Accessibility APIs
   - Simulates user interactions with System Settings
   - Monitors for authorization dialogs and prompts

### Hardware Classification

The tool automatically detects and adapts to different Mac configurations:
- **Model identification** and processor information
- **Feature detection** (Battery, Touch ID, Thunderbolt, etc.)
- **Hardware-specific setting filtering** (skips unavailable options)
- **Comprehensive compatibility matrix** for different Mac models

## 📊 Reports and Analysis

### Discovery Reports

Each discovery session generates a comprehensive report including:

```json
{
  "discovery_session": {
    "start_time": "2025-09-03T10:30:00",
    "end_time": "2025-09-03T11:15:00",
    "duration_seconds": 2700,
    "total_authorizations_found": 47,
    "hardware_profile": { ... },
    "unavailable_features": [ ... ]
  },
  "authorization_results": [
    {
      "element_path": "Privacy & Security > Camera",
      "element_name": "Camera Access",
      "authorization_events": [
        {
          "right_name": "kTCCServiceCamera",
          "right_description": "Camera access",
          "context": "TCC Framework",
          "timestamp": "2025-09-03T10:35:22"
        }
      ]
    }
  ]
}
```

### Version Comparison

The web dashboard enables comparison between different macOS versions to identify:
- **New authorization requirements** introduced in updates
- **Removed or modified** authorization points
- **Changes in authorization behavior** between versions

## 🔧 Configuration

### Command Line Options

```bash
python main.py [OPTIONS]

Options:
  --mode {discover,web,both}    Mode to run (default: both)
  --port INTEGER                Port for web application (default: 5000)
  --debug                       Enable debug mode
  --log-level {DEBUG,INFO,WARNING,ERROR}  Logging level (default: INFO)
```

### Environment Variables

```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"  # Required for module imports
```

## 🛠️ Development

### Project Structure

- **Core Logic**: `src/core/` contains the main discovery and monitoring logic
- **Web Interface**: `src/web/` contains the Flask application and templates
- **Data Storage**: `data/` directory for reports and exports
- **Logging**: `logs/` directory for application logs

### Adding New Features

1. **New Authorization Detection**: Extend `SystemLevelMonitor` class
2. **Additional UI Elements**: Modify `SystemSettingsNavigator` class
3. **Web Dashboard Features**: Update Flask routes in `web/app.py`
4. **Hardware Support**: Enhance `HardwareProfileManager` class

### Testing

```bash
# Run discovery in test mode
python main.py --mode discover --debug

# Test specific components
python -m pytest tests/  # (when test suite is added)
```

## 🔍 Troubleshooting

### Common Issues

1. **"Failed to open System Settings"**
   - Ensure System Settings is not already open
   - Grant Accessibility permissions to Terminal/iTerm
   - Restart Terminal application

2. **"Limited log access"**
   - Grant Developer Tools permission to Terminal
   - Run with administrator privileges if needed
   - Check Console.app for authorization events

3. **"Authorization detection accuracy low"**
   - Ensure all privacy permissions are granted
   - Run discovery when system is not under heavy load
   - Check for conflicting endpoint protection software

4. **"Web dashboard not accessible"**
   - Check if port 5000 is available
   - Use `--port` option to specify different port
   - Verify Flask installation with `pip list | grep Flask`

### Debug Mode

Enable debug mode for detailed logging:

```bash
python main.py --debug --log-level DEBUG
```

This provides verbose output including:
- Detailed AppleScript execution results
- System log monitoring details
- UI automation step-by-step progress
- Hardware detection diagnostics

### Log Files

Application logs are stored in:
- **Main log**: `auth_discovery.log`
- **Discovery reports**: `data/auth_discovery_report_*.json`
- **System logs**: Use Console.app to monitor system authorization events

## 📋 Known Limitations

1. **Apple API Dependencies**: Some features depend on undocumented Apple APIs
2. **Hardware-Specific Testing**: Some authorization points only trigger on specific hardware
3. **System Version Changes**: Apple may modify System Settings structure between versions
4. **Performance Impact**: Deep system scanning may temporarily affect system responsiveness

## 🔒 Security Considerations

- **Non-Destructive**: All discovery actions are designed to be reversible
- **Permission Handling**: Respects existing system security settings
- **Data Privacy**: All discovered data is stored locally
- **System Integrity**: No modification of system security configurations

## 📄 License

This project is developed for BeyondTrust EPM testing purposes. See license terms for usage restrictions.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with appropriate tests
4. Submit a pull request with detailed description

## 📞 Support

For issues and questions:
1. Check the troubleshooting section above
2. Review application logs in debug mode
3. Create an issue with detailed system information and error logs

---

**Note**: This tool is specifically designed for BeyondTrust EPM testing and requires appropriate permissions and system access. Always run in a controlled testing environment.
