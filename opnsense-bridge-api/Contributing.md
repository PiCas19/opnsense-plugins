# Contributing to OPNsense Monitoring Bridge

Thank you for your interest in contributing to the OPNsense Monitoring Bridge project! This document outlines the guidelines for contributing code, reporting issues, and suggesting features. Your contributions help improve this secure, scalable solution for monitoring and managing OPNsense firewalls in a DMZ environment.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Contact](#contact)

## Code of Conduct
We are committed to fostering an open and inclusive community. Please be respectful and professional in all interactions. Any behavior that violates this principle may result in exclusion from the project.

## How to Contribute
Contributions can include code improvements, bug fixes, new features, documentation updates, or test enhancements. Follow these steps to contribute:

1. **Fork the Repository**:
   ```bash
   git clone https://github.com/your-org/opnsense-monitoring-bridge.git
   cd opnsense-monitoring-bridge
   ```

2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Commit Changes**:
   Use clear, descriptive commit messages:
   ```bash
   git commit -m "Add your feature description"
   ```

4. **Push to Your Fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request**:
   Submit a pull request to the `main` branch with a detailed description of your changes.

## Reporting Bugs
To report a bug:
1. Check the [Issues](https://git.consoli.ch/students/20250400_lavsem/moretto/-/issues) page to ensure the bug hasn't been reported.
2. Open a new issue with:
   - A clear title (e.g., "API /health endpoint returns 500 on invalid config").
   - A detailed description, including steps to reproduce, expected behavior, and actual behavior.
   - Relevant logs from `logs/bridge.log` or `logs/emergency.log`:
     ```bash
     tail -f logs/bridge.log
     ```
   - Your environment (e.g., OPNsense version, Docker version, `.env` settings).

## Suggesting Features
To suggest a feature:
1. Open an issue on the [Issues](https://git.consoli.ch/students/20250400_lavsem/moretto/-/issues) page.
2. Use a clear title (e.g., "Add support for Zabbix monitoring integration").
3. Describe the feature, its use case, and any proposed implementation details.
4. Tag the issue with the "enhancement" label.

## Development Setup
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-org/opnsense-monitoring-bridge.git
   cd opnsense-monitoring-bridge
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment**:
   Copy `.env.example` to `.env` and set the required variables:
   ```bash
   cp .env.example .env
   nano .env
   ```
   Example:
   ```plaintext
   BRIDGE_IP=172.16.216.10
   BRIDGE_PORT=8443
   JWT_SECRET_KEY=your-super-secure-jwt-secret-key
   OPNSENSE_HOST=192.168.216.1
   ```

4. **Generate Certificates**:
   ```bash
   ./scripts/setup-bridge.sh
   ```

5. **Run Tests**:
   Set `TEST_MODE=true` and `MOCK_OPNSENSE_API=true` in `.env`, then run:
   ```bash
   pytest -v tests/
   ```

6. **Run Locally**:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
   ```

See [README.md](README.md) and [Deployment Guide](docs/deployment/deployment.md) for details.

## Pull Request Process
1. Ensure your code follows the project's coding standards (e.g., PEP 8 for Python).
2. Include tests for new features or bug fixes in the `tests/` directory.
3. Update documentation (e.g., `docs/api/endpoints.md`) if new endpoints or configurations are added.
4. Run tests to verify no regressions:
   ```bash
   pytest -v tests/
   ```
5. Submit a pull request with:
   - A clear title and description.
   - Reference to related issues (e.g., "Fixes #123").
   - A summary of changes and their impact.

The maintainers will review your pull request and provide feedback. Ensure all CI checks pass (e.g., tests, linting).

## Contact
For questions or further assistance, contact the project maintainer:
- **Name**: Pierpaolo Casati
- **Email**: pierpaolo.casati@student.supsi.ch

We appreciate your contributions to making the OPNsense Monitoring Bridge better!