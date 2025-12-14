# Firewall Extension Documentation

This documentation describes the features and usage of the Firewall extension for TYPO3.

## Structure

- Start: see `Index.rst`
- Features: see `Features.rst`
- Backend: see `Backend.rst`
- Phirewall: see `Phirewall.rst`

## Main features

The main features of the Firewall extension are:

- Integration of the Phirewall package (see `Phirewall.rst`)
- Management of static block patterns in the TYPO3 backend
- Support for various pattern types (IP, CIDR, path, header, user agent, regex)
- Expiration date for patterns (`expiresAt`)
- Immediate activation and enforcement of rules
- Compatible with TYPO3 core conventions

## Configuration overview

- Core Phirewall configuration: `config/system/phirewall.php`
- Static custom patterns managed by this extension: `config/system/phirewall.patterns.php`
