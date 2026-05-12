# Static Docker Compose Analyser
Fourth year Dissertation project - Static Docker Compose Analyser

# Static Docker Compose Analyser

A lightweight Python static analysis tool for detecting security misconfigurations in Docker Compose files.

## Installation

Requires Python 3.8+ and PyYAML.

pip install pyyaml

## Usage 

To scan a single file:
python main.py path/to/docker-compose.yml

To Scan a folder of compose files:
python main.py path/to/folder

Normal Output is to terminal
Alternate way generates a HTML report:
python main.py path/to/folder --report

## Checks that are implemented
The tool implements seven misconfiguration checks:
- Privileged container execution
- Docker socket exposure
- Unsafe host volume mounts
- Excessive Linux capabilities
- Host network mode
- Missing resource limits
- Containers running as root

Each check is implemented as a separate module in the `checks/` directory.

## Project

This tool was developed as part of a BSc (Hons) Digital Forensics & Cyber Security dissertation at TU Dublin.
