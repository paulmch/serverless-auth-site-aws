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
4. Ensure all tests pass (`pytest`) and the stack still synthesizes (`npm run synth`)
5. Update documentation if you've changed APIs or behavior
6. Submit your pull request

## Development Setup

### Prerequisites

- Node.js 22+
- Python 3.13 (matches the Lambda runtime the stack deploys)
- AWS CLI configured with credentials

The AWS CDK CLI comes from `devDependencies` - run it as `npx cdk` rather than
installing it globally, so it stays on the version pinned in the lockfile.

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/serverless-auth-site-aws.git
cd serverless-auth-site-aws

# Install Node dependencies
npm ci

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

### Checking the Infrastructure

```bash
npm run typecheck
npm run synth
```

CI runs the tests, the typecheck, `cdk synth` and `npm audit` on every pull
request.

### Code Style

- Python: Follow PEP 8
- TypeScript: Use the project's existing style

## Questions?

Feel free to open an issue for any questions about contributing.
