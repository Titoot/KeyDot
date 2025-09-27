# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-09-04

### Added
- Initial release of KeyDot.
- Support for key extraction from Windows 64-bit PE files.
- Support for key extraction from WebAssembly (.wasm) files.
- Command-line options for debug logging (`--debug`) and timers (`--timers`).

## [1.0.1] - 2025-09-27

### Fixed
- RIP-relative load functions
- updated scanning for MOV/LEA instructions