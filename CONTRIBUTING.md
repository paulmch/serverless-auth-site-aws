# Contributing to serverless-auth-site-aws

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Your environment (Node.js version, Python version, AWS region)
- Relevant logs or error messages

### Suggesting Features

Feature requests are welcome. Please include:

- A clear description of the feature
- The problem it solves
- Any alternative solutions you've considered

### Pull Requests

1. Fork the repository and create your branch from `main`
2. Make your changes
3. Add or update tests as needed
4. Ensure all tests pass (`pytest`)
5. Update documentation if you've changed APIs or behavior
6. Submit your pull request

## Development Setup

### Prerequisites

- Node.js 18+
- Python 3.9+
- AWS CLI configured with credentials
- AWS CDK CLI (`npm install -g aws-cdk`)

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/aws-secure-static-site.git
cd aws-secure-static-site

# Install Node dependencies
npm install

# Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or: .venv\Scripts\activate  # Windows

# Install test dependencies
pip install -r tests/requirements.txt
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=lambda --cov-report=html

# Run specific test file
pytest tests/test_authorizer.py -v
```

### Code Style

- Python: Follow PEP 8
- TypeScript: Use the project's existing style

## Questions?

Feel free to open an issue for any questions about contributing.
