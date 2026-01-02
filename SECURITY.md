# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead:

1. **GitHub Private Vulnerability Reporting**: Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature on this repository
2. **Email**: If private reporting is not available, contact the maintainer directly

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected components (Lambda functions, CDK stack, etc.)
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- Acknowledgment within 48 hours
- Regular updates on progress
- Credit in the fix (unless you prefer anonymity)

## Security Considerations

This project handles authentication tokens and session data. Key security areas:

- **Lambda Authorizer** (`lambda/authorizer.py`): JWT validation and session verification
- **Session Storage** (`DynamoDB`): Server-side token storage
- **Auth Callback** (`lambda/auth_callback.py`): OAuth2 token exchange

See the README for recommended production hardening measures.

## Scope

This security policy covers:

- The CDK infrastructure code
- Lambda function code
- Authentication and session handling logic

Out of scope:

- AWS service vulnerabilities (report to AWS)
- Dependencies (report to respective maintainers)
