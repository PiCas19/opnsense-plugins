# OPNsense Security Plugins Suite

A comprehensive collection of advanced security plugins for OPNsense firewall, providing enhanced network inspection, threat detection, web application protection, and network segmentation capabilities.

## 🔒 Security Plugins Overview

This repository contains four specialized security plugins designed to extend OPNsense capabilities:

- **🔍 AdvInspector** (`os-advinspector`) - Advanced packet inspection and rule management
- **🛡️ DeepInspector** (`os-deepinspector`) - Deep packet inspection with threat analysis
- **🌐 NetZones** (`os-netzones`) - Network segmentation and zone-based policies
- **🛡️ WebGuard** (`os-webguard`) - Web application firewall and threat protection

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Installation](#quick-installation)
- [Manual Installation](#manual-installation)
- [Plugin Descriptions](#plugin-descriptions)
- [Configuration](#configuration)
- [API Integration](#api-integration)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## 🔧 Prerequisites

### System Requirements

- **OPNsense**: 23.1 or higher
- **opnsense-code**: Plugin development framework
- **Git**: Version control for plugin management
- **Make**: Build system for package compilation
- **PHP**: 8.1+ (included with OPNsense)
- **Python**: 3.9+ (for backend scripts)

### Required Permissions

- Root access to OPNsense system
- Write permissions to `/usr/plugins/`
- Network access for plugin dependencies

---

## 🚀 Quick Installation

### Automated Installation

Clone the repository and run the installation script:

```bash
# Clone the repository
git clone https://github.com/your-repo/opnsense-plugins.git
cd opnsense-plugins

# Run the installation script
sudo ./install_signed_plugins.sh
```

### Installation Script Options

```bash
# Install all plugins (default)
sudo ./install_signed_plugins.sh

# Install specific plugins
sudo ./install_signed_plugins.sh --plugins="advinspector,webguard"

# Verbose output
sudo ./install_signed_plugins.sh --verbose

# Dry run (preview only)
sudo ./install_signed_plugins.sh --dry-run
```

---

## 🔨 Manual Installation

### Step 1: Install opnsense-code

```bash
# Install the development framework
pkg install opnsense-code

# Verify installation
opnsense-code --version
```

### Step 2: Clone Repository

```bash
# Clone the plugins repository
git clone https://github.com/your-repo/opnsense-plugins.git
cd opnsense-plugins

# Create plugins directory
sudo mkdir -p /usr/plugins/security
sudo chown $(whoami):wheel /usr/plugins/security
```

### Step 3: Install Plugins

```bash
# Copy plugins to the system directory
sudo cp -r os-* /usr/plugins/security/

# Set proper permissions
sudo chown -R root:wheel /usr/plugins/security/
sudo chmod -R 755 /usr/plugins/security/
```

### Step 4: Build and Package Each Plugin

For each plugin, follow these steps:

#### AdvInspector Plugin

```bash
cd /usr/plugins/security/os-advinspector

# Initialize git repository
git init
git add .
git commit -m "Initial commit: os-advinspector plugin"

# Clean and build
make clean
make package

# Verify package creation
ls -la work/pkg/*.pkg
```

#### DeepInspector Plugin

```bash
cd /usr/plugins/security/os-deepinspector

# Initialize git repository
git init
git add .
git commit -m "Initial commit: os-deepinspector plugin with deep packet analysis"

# Clean and build
make clean
make package

# Verify package creation
ls -la work/pkg/*.pkg
```

#### NetZones Plugin

```bash
cd /usr/plugins/security/os-netzones

# Initialize git repository
git init
git add .
git commit -m "Initial commit: os-netzones plugin for network segmentation"

# Clean and build
make clean
make package

# Verify package creation
ls -la work/pkg/*.pkg
```

#### WebGuard Plugin

```bash
cd /usr/plugins/security/os-webguard

# Initialize git repository
git init
git add .
git commit -m "Initial commit: os-webguard plugin for web application protection"

# Clean and build
make clean
make package

# Verify package creation
ls -la work/pkg/*.pkg
```

### Step 5: Install Packages

```bash
# Install all built packages
for plugin in /usr/plugins/security/os-*/work/pkg/*.pkg; do
    echo "Installing $plugin..."
    pkg add "$plugin"
done

# Restart required services
service configd restart
configctl plugin reload
```

### Step 6: Execute Installation Script

```bash
# Run the final installation script
sudo ./install_signed_plugins.sh
```

---

## 📦 Plugin Descriptions

### 🔍 AdvInspector (os-advinspector)

**Advanced Packet Inspection and Rule Management**

#### Features
- Real-time packet inspection engine
- Custom rule creation and management
- Alert system for suspicious activity
- Traffic flow analysis
- Configurable inspection thresholds

#### Components
- **Controllers**: Web interface and API endpoints
- **Models**: Configuration management and data validation
- **Scripts**: Backend inspection engine (`packet_inspector.py`)
- **Views**: Web dashboard for rule management

#### Use Cases
- Network traffic monitoring
- Custom security rule enforcement
- Incident detection and alerting
- Compliance reporting

---

### 🛡️ DeepInspector (os-deepinspector)

**Deep Packet Inspection with Industrial Protocol Support**

#### Features
- Layer 7 protocol analysis
- Industrial protocol inspection (Modbus, DNP3, etc.)
- Machine learning-based threat detection
- Real-time metrics and statistics
- Signature-based detection engine

#### Components
- **Engine**: Core inspection engine (`deepinspector_engine.py`)
- **Analytics**: Threat analysis and reporting
- **Dashboard**: Real-time monitoring interface
- **API**: RESTful endpoints for integration

#### Use Cases
- Industrial network security
- SCADA system protection
- Advanced persistent threat (APT) detection
- Protocol anomaly detection

---

### 🌐 NetZones (os-netzones)

**Network Segmentation and Zone-Based Security**

#### Features
- Automatic network zone discovery
- Inter-zone policy management
- Dynamic zone assignment
- Traffic flow control between zones
- Zone-based access control

#### Components
- **Engine**: Zone evaluation engine (`netzones_evaluator.py`)
- **Dashboard**: Zone topology visualization
- **Policies**: Inter-zone communication rules
- **Simulator**: Network zone testing (`simulate_netzones.py`)

#### Use Cases
- Network micro-segmentation
- Zero-trust architecture implementation
- Compliance with security frameworks
- Automated network isolation

---

### 🛡️ WebGuard (os-webguard)

**Web Application Firewall and Threat Protection**

#### Features
- Layer 7 web application protection
- Real-time threat blocking
- Behavioral analysis engine
- Covert channel detection
- Geographic threat intelligence
- Custom WAF rules

#### Components
- **WAF Engine**: Core protection engine (`web_guard_engine.py`)
- **Threat Intel**: Geographic and behavioral analysis
- **Blocking**: Dynamic IP and threat blocking
- **Dashboard**: Real-time attack visualization

#### Use Cases
- Web application protection
- API security
- DDoS mitigation
- Geographic access control
- Threat intelligence integration

---

## ⚙️ Configuration

### Initial Setup

After installation, configure each plugin through the OPNsense web interface:

1. **Navigate to System → Plugin Management**
2. **Verify plugin installation status**
3. **Access plugin configuration pages**

### Plugin Configuration Paths

```
AdvInspector:    Services → AdvInspector
DeepInspector:   Services → DeepInspector  
NetZones:        Services → NetZones
WebGuard:        Services → WebGuard
```

### Basic Configuration Steps

#### 1. AdvInspector Setup

```bash
# Navigate to Services → AdvInspector → Settings
# Configure inspection rules
# Enable packet monitoring
# Set alert thresholds
```

#### 2. DeepInspector Setup

```bash
# Navigate to Services → DeepInspector → Settings
# Configure protocol detection
# Enable industrial protocol inspection
# Set analysis thresholds
```

#### 3. NetZones Setup

```bash
# Navigate to Services → NetZones → Dashboard
# Define network zones
# Configure inter-zone policies
# Enable automatic zone detection
```

#### 4. WebGuard Setup

```bash
# Navigate to Services → WebGuard → Settings
# Configure WAF rules
# Enable threat protection
# Set geographic restrictions
```

### Advanced Configuration

#### Environment Variables

```bash
# AdvInspector configuration
export ADVINSPECTOR_LOG_LEVEL=INFO
export ADVINSPECTOR_MAX_RULES=1000

# DeepInspector configuration  
export DEEPINSPECTOR_SIGNATURES_UPDATE=daily
export DEEPINSPECTOR_ANALYSIS_DEPTH=full

# NetZones configuration
export NETZONES_AUTO_DISCOVERY=enabled
export NETZONES_POLICY_MODE=strict

# WebGuard configuration
export WEBGUARD_THREAT_INTEL=enabled
export WEBGUARD_GEO_BLOCKING=enabled
```

#### Configuration Files

```bash
# Plugin configuration files location
/usr/local/etc/advinspector/
/usr/local/etc/deepinspector/
/usr/local/etc/netzones/
/usr/local/etc/webguard/

# Log files location
/var/log/advinspector/
/var/log/deepinspector/
/var/log/netzones/
/var/log/webguard/
```

---

## 🔌 API Integration

### REST API Endpoints

Each plugin provides RESTful API endpoints for integration:

#### AdvInspector API

```bash
# Get rules
GET /api/advinspector/rules

# Create rule
POST /api/advinspector/rules
{
  "name": "Custom Rule",
  "action": "block",
  "protocol": "tcp",
  "port": "80"
}

# Get alerts
GET /api/advinspector/alerts

# Get service status
GET /api/advinspector/service/status
```

#### DeepInspector API

```bash
# Get analysis results
GET /api/deepinspector/analysis

# Get metrics
GET /api/deepinspector/metrics

# Update signatures
POST /api/deepinspector/signatures/update

# Get industrial stats
GET /api/deepinspector/industrial/stats
```

#### NetZones API

```bash
# Get zones
GET /api/netzones/zones

# Create zone
POST /api/netzones/zones
{
  "name": "DMZ",
  "network": "192.168.100.0/24",
  "policy": "restricted"
}

# Get dashboard data
GET /api/netzones/dashboard
```

#### WebGuard API

```bash
# Get threats
GET /api/webguard/threats

# Block IP
POST /api/webguard/blocking/ip
{
  "ip": "192.168.1.100",
  "duration": "3600",
  "reason": "malicious activity"
}

# Get WAF stats
GET /api/webguard/waf/stats

# Manage whitelist
POST /api/webguard/whitelist
```

### API Authentication

```bash
# Use OPNsense API key authentication
curl -X GET "https://opnsense.local/api/advinspector/rules" \
  -H "Authorization: ApiKey your-api-key:your-api-secret"
```

---

## 🐛 Troubleshooting

### Common Issues

#### Plugin Installation Failures

**Issue**: Package build fails
```
Error: make: *** [package] Error 1
```

**Solution**:
```bash
# Check dependencies
pkg install gmake git

# Verify git repository status
git status
git log --oneline

# Clean and retry
make clean
make package
```

#### Service Start Failures

**Issue**: Plugin service won't start
```
Error: Service advinspector failed to start
```

**Solution**:
```bash
# Check service status
service advinspector status

# Check logs
tail -f /var/log/advinspector/advinspector.log

# Restart configuration daemon
service configd restart
configctl plugin reload
```

#### Permission Issues

**Issue**: Permission denied errors
```
Error: Permission denied accessing /usr/plugins/
```

**Solution**:
```bash
# Fix ownership
sudo chown -R root:wheel /usr/plugins/security/

# Fix permissions
sudo chmod -R 755 /usr/plugins/security/

# Verify ACL settings
getfacl /usr/plugins/security/
```

### Debug Commands

```bash
# Check plugin status
opnsense-code list

# Verify package integrity
pkg info | grep -E "(advinspector|deepinspector|netzones|webguard)"

# Check configuration
configctl plugin list

# Monitor logs in real-time
tail -f /var/log/configd.log
tail -f /var/log/system.log
```

### Log Analysis

```bash
# AdvInspector logs
tail -f /var/log/advinspector/packet_inspector.log

# DeepInspector logs  
tail -f /var/log/deepinspector/engine.log

# NetZones logs
tail -f /var/log/netzones/evaluator.log

# WebGuard logs
tail -f /var/log/webguard/threats.log
```

---

## 🔄 Development

### Development Environment Setup

```bash
# Clone for development
git clone https://github.com/your-repo/opnsense-plugins.git
cd opnsense-plugins

# Create development branch
git checkout -b feature/new-enhancement

# Install development dependencies
pip install -r requirements-dev.txt
```

### Plugin Development Workflow

#### 1. Create New Plugin

```bash
# Use plugin template
cp -r template/os-template os-newplugin

# Update metadata
vi os-newplugin/meta.json
vi os-newplugin/pkg-descr
```

#### 2. Development Cycle

```bash
# Make changes
# Test locally
make test

# Build package
make clean
make package

# Install for testing
pkg add work/pkg/*.pkg

# Commit changes
git add .
git commit -m "Add new feature: description"
```

#### 3. Testing

```bash
# Run unit tests
cd scripts/tests/
python -m pytest test_*.py

# Run integration tests
./run_integration_tests.sh

# Performance testing
./benchmark_plugins.sh
```

### Plugin Structure

```
os-pluginname/
├── Makefile              # Build configuration
├── meta.json             # Plugin metadata
├── pkg-descr             # Package description
└── src/
    ├── etc/rc.d/         # Service startup scripts
    └── opnsense/
        ├── mvc/app/
        │   ├── controllers/  # Web and API controllers
        │   ├── models/       # Data models and configuration
        │   └── views/        # Web interface templates
        ├── scripts/          # Backend processing scripts
        └── service/conf/     # Service configuration
```

### Code Standards

#### PHP Code (Controllers/Models)

```php
<?php
namespace OPNsense\PluginName;

use OPNsense\Base\BaseController;
use OPNsense\Core\Config;

class SettingsController extends BaseController
{
    public function indexAction()
    {
        // Implementation
    }
}
```

#### Python Code (Scripts)

```python
#!/usr/local/bin/python3
"""
Plugin script with proper documentation.
"""

import logging
import sys

def main():
    """Main function with error handling."""
    try:
        # Implementation
        pass
    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Contributing

1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit changes** (`git commit -m 'Add amazing feature'`)
4. **Push to branch** (`git push origin feature/amazing-feature`)
5. **Create Pull Request**

---

## 📋 Installation Checklist

### Pre-Installation

- [ ] OPNsense 23.1+ running
- [ ] Root access available
- [ ] Network connectivity verified
- [ ] Sufficient disk space (>500MB)

### Installation Process

- [ ] opnsense-code installed
- [ ] Repository cloned
- [ ] Plugins copied to `/usr/plugins/security/`
- [ ] Git repositories initialized for each plugin
- [ ] All plugins built successfully
- [ ] Packages installed via pkg
- [ ] Services restarted
- [ ] Installation script executed

### Post-Installation

- [ ] All plugins visible in web interface
- [ ] API endpoints responding
- [ ] Log files created
- [ ] Services starting properly
- [ ] Configuration accessible


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OPNsense development team for the excellent plugin framework
- Community contributors for testing and feedback
- Security researchers for vulnerability reporting

---

**Plugin Suite Version**: 1.0.0  
**OPNsense Compatibility**: 25.1.10  
**Last Updated**: 2025 
**Maintainer**: Pierpoalo Casati
