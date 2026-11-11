# Contributing to Security Advisor Auditor

Thank you for your interest in contributing to **Security Advisor Auditor**! We welcome contributions from everyone.

## 📋 How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates
2. **Create a new issue** with:
   - Clear title describing the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Screenshots or logs (redact sensitive information)
   - Environment details (Python version, OS, etc.)

### Suggesting Features

1. **Open an issue** with the `enhancement` label
2. Describe:
   - The problem you're trying to solve
   - Your proposed solution
   - Use cases and benefits

### Submitting Pull Requests

1. **Fork the repository** and create a feature branch (`git checkout -b feature/your-feature`)
2. **Add tests** for your changes (all tests must pass)
3. **Follow code style**:
   - Use consistent indentation (4 spaces)
   - Add type hints where applicable
   - Include docstrings for public functions/classes
   - Follow existing naming conventions
4. **Update documentation** if applicable
5. **Run all tests**: `python -B -m unittest discover -s tests -v`
6. **Run type checking**: `mypy scripts/`
7. **Commit messages**: Use clear, descriptive messages following [Conventional Commits](https://www.conventionalcommits.org/)
8. **Create a PR** with:
   - Clear title and description
   - Reference to related issue (if any)
   - Screenshots for UI changes
   - Breaking changes clearly marked

## 🏗️ Development Setup

```bash
# Clone the repository
git clone https://github.com/bitacoradigitalia-coder/security-advisor-auditor.git
cd security-advisor-auditor

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install mypy pytest pytest-cov

# Run tests
python -B -m unittest discover -s tests -v

# Run type checking
mypy scripts/

# Run with coverage
pytest tests/ --cov=scripts --cov-report=html
```

## 📁 Project Structure

```
security-advisor-auditor/
├── scripts/                  # Main executable code
│   ├── audit.py             # CLI entry point
│   ├── security_auditor/    # Static analysis engine
│   ├── pentesting/         # Active scanning modules
│   ├── bugbounty/           # Bug bounty management
│   ├── reporting/          # Report generation
│   ├── sca/                 # Software Composition Analysis
│   └── core/                # Core utilities
├── docs/                    # Documentation
├── tests/                   # Test suite
├── schemas/                 # JSON schemas
├── references/              # Methodologies and standards
└── examples/                # Example files
```

## 🎯 Contribution Guidelines

### Code Style
- **Python**: Follow PEP 8
- **Type hints**: Use for all public functions and classes
- **Docstrings**: Use Google-style docstrings
- **Imports**: Group by type (standard, third-party, local)
- **Line length**: Maximum 100 characters

### Testing
- All new code must have corresponding tests
- Tests should cover both happy paths and edge cases
- Use descriptive test names
- Mock external dependencies where appropriate

### Security
- **Never commit sensitive data** (credentials, API keys, tokens)
- **Sanitize all inputs** in security-related code
- **Follow principle of least privilege**
- **Validate all assumptions**

### Documentation
- Update README.md if adding new features
- Update docs/ for significant changes
- Keep CHANGELOG.md up to date
- Use clear, concise language

## 🤝 Code of Conduct

This project follows a Code of Conduct to ensure a welcoming and inclusive community. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## 📜 License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## 🙏 Recognition

All meaningful contributions will be recognized in the CHANGELOG and contributors list.

---

**Happy Coding!** 🚀
