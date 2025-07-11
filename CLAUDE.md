# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

EmailHarvester is a Python 3 tool designed to retrieve domain email addresses from various search engines. It uses a plugin-based architecture for extensibility and includes security improvements like plugin allowlisting and improved regex patterns.

## Key Commands

### Installation
```bash
pip install -r requirements.txt
```

### Running EmailHarvester
```bash
# Basic usage - search domain in Google
./EmailHarvester.py -d example.com -e google

# Search all engines
./EmailHarvester.py -d example.com -e all

# Search with limits and save results
./EmailHarvester.py -d example.com -e all -l 200 -s emails.txt

# Use proxy
./EmailHarvester.py -d example.com -e all -x http://127.0.0.1:8080

# List available plugins
./EmailHarvester.py -p
```

### Docker
```bash
docker build -t EmailHarvester .
docker run -it EmailHarvester -d example.com
```

## Architecture

### Core Components

1. **EmailHarvester.py** - Main entry point containing:
   - `myparser` class: Handles email extraction and result parsing
   - Plugin loading system with security allowlist (`ALLOWED_PLUGINS`)
   - Command-line argument processing
   - Result export functionality (TXT/XML)

2. **Plugin System** - Located in `plugins/` directory:
   - Each plugin inherits common structure with `config` and `app_emailharvester` globals
   - Plugins implement search functionality for specific engines/sites
   - Common methods: `__init__`, `do_search`, `process`, `get_emails`
   - Allowed plugins: ask, baidu, bing, dogpile, exalead, github, googleplus, googles, instagram, linkedin, reddit, twitter, yahoo, youtube

### Security Features
- Plugin allowlist prevents loading of unauthorized plugins
- Improved regex patterns to prevent ReDoS attacks
- Secure logging configuration
- Input validation for domains and proxies

### Dependencies
- termcolor - Terminal color output
- colorama - Windows color support
- requests - HTTP requests
- validators - URL/domain validation

## Development Notes

### Adding New Plugins
1. Create new plugin file in `plugins/` directory
2. Add plugin name to `ALLOWED_PLUGINS` set in EmailHarvester.py
3. Implement required methods following existing plugin patterns
4. Plugin must set `config` and `app_emailharvester` globals

### Testing
No formal test suite exists. Manual testing recommended:
```bash
# Test specific engine
./EmailHarvester.py -d test.com -e [plugin_name]

# Verify plugin loading
./EmailHarvester.py -p
```

### Common Modifications
- Search result limits are controlled by `-l` parameter
- User-Agent strings can be customized with `-u` parameter
- Proxy configuration via `-x` parameter
- Results saved to both TXT and XML formats when using `-s`