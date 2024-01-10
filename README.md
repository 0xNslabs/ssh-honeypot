# Simple SSH Honeypot Server

## Introduction
The Simple SSH Honeypot Server is a script for cybersecurity enthusiasts and professionals to analyze SSH-based network interactions. Utilizing Python and the Twisted framework, this script simulates an SSH server, logging unauthorized access attempts and credentials. This is a valuable resource for understanding SSH vulnerabilities and intrusion techniques.

## Features
- **Low-Interaction Honeypot**: Simulates an SSH server for safely logging authentication attempts.
- **Customizable Configuration**: Host and port settings can be adjusted through command-line arguments.
- **Detailed Logging**: Records all SSH interactions, including usernames and passwords.
- **Real-Time Monitoring**: Enables immediate logging and reporting of SSH activities for swift detection of anomalies.
- **Educational Tool**: Great for learning about SSH security issues and network reconnaissance methods.

## Requirements
- Python 3.x
- Twisted Python library

## Installation
To install and set up the SSH honeypot server, execute the following commands:

```bash
git clone https://github.com/0xNslabs/ssh-honeypot.git
cd ssh-honeypot
pip install twisted
```

## Usage
Start the server with these optional parameters for the host and port. By default, it binds to all interfaces (0.0.0.0) on port 2222.

```bash
python3 ssh.py --host 0.0.0.0 --port 2222
```

## Logging
All SSH interactions are logged in `ssh_honeypot.log`, providing detailed records of login attempts and commands issued to the server.

## Simple SSH Honeypot In Action
![Simple SSH Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/ssh-honeypot/main/PoC.png)
*This image displays the Simple SSH Honeypot Server capturing real-time SSH login attempts and commands.*

## Security and Compliance
- **Caution**: Employ this honeypot in secure and controlled environments for research and educational purposes.
- **Compliance**: Ensure all deployments comply with local and international legal standards.

## License
This project is released under the MIT License. For more details, see the LICENSE file.