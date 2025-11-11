# Python Firewall Prototype for Windows

A comprehensive firewall prototype built with Python and Tkinter, designed for educational purposes and network security learning.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

## Features

- **Rule-Based Packet Filtering**: Create custom rules based on IP addresses, ports, protocols, and traffic direction
- **Intuitive GUI**: Easy-to-use interface built with Tkinter
- **Real-Time Monitoring**: Live activity log showing allowed and blocked traffic
- **Statistics Dashboard**: Track total, allowed, and blocked packets
- **Flexible Rule Management**: Add, remove, enable/disable rules on the fly
- **Import/Export Rules**: Save and load rule configurations in JSON format
- **Default Policy Configuration**: Set global ALLOW or BLOCK policy
- **Hit Counter**: Track how many times each rule has been triggered
- **Wildcard Support**: Use wildcards in IP addresses (e.g., 192.168.1.*)

## Screenshots

### Main Interface
The firewall provides a comprehensive dashboard with rule management, statistics, and activity logging.

### Rule Management
Easily create rules with specific criteria including protocol, source/destination IPs and ports, and traffic direction.

## Requirements

- Python 3.7 or higher
- Windows OS
- tkinter (usually included with Python)

### Optional (for production deployment)
- `pydivert` or `WinDivert` - For real packet interception
- `scapy` - For advanced packet analysis
- Administrator privileges - Required for packet capture

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Rikiza89/Firewall-prototype.git
cd Firewall-prototype
```

2. Ensure Python 3.7+ is installed:
```bash
python --version
```

3. Run the firewall:
```bash
python firewall.py
```

## Usage

### Starting the Firewall

1. Launch the application by running `firewall.py`
2. Click the **"Start Firewall"** button to begin monitoring
3. Monitor traffic in the Activity Log panel
4. View statistics in the Statistics panel

### Managing Rules

#### Adding a Rule
1. Click **"Add Rule"** button
2. Fill in the rule details:
   - **Name**: Descriptive name for the rule
   - **Action**: ALLOW or BLOCK
   - **Protocol**: TCP, UDP, ICMP, or ALL
   - **Source IP**: IP address or "ANY" (supports wildcards like 192.168.1.*)
   - **Source Port**: Port number or "ANY"
   - **Destination IP**: IP address or "ANY"
   - **Destination Port**: Port number or "ANY"
   - **Direction**: INBOUND, OUTBOUND, or BOTH
3. Click **"Save"**

#### Removing a Rule
1. Select a rule from the list
2. Click **"Remove Rule"**
3. Confirm the deletion

#### Enabling/Disabling a Rule
1. Select a rule from the list
2. Click **"Toggle Enable"**
3. The rule will be disabled but not deleted

### Saving and Loading Rules

- **Save Rules**: File → Save Rules (saves to `firewall_rules.json`)
- **Load Rules**: File → Load Rules (loads from `firewall_rules.json`)

### Default Policy

Set the default action for traffic that doesn't match any rule:
- **ALLOW**: Permit all unmatched traffic (default)
- **BLOCK**: Block all unmatched traffic

## Rule Examples

### Block Specific IP
- **Name**: Block Malicious IP
- **Action**: BLOCK
- **Protocol**: ALL
- **Source IP**: 192.168.1.100
- **Destination**: ANY
- **Direction**: BOTH

### Allow Web Traffic
- **Name**: Allow HTTPS
- **Action**: ALLOW
- **Protocol**: TCP
- **Destination Port**: 443
- **Direction**: OUTBOUND

### Block Telnet
- **Name**: Block Telnet
- **Action**: BLOCK
- **Protocol**: TCP
- **Destination Port**: 23
- **Direction**: BOTH

### Allow Local Network
- **Name**: Allow LAN
- **Action**: ALLOW
- **Protocol**: ALL
- **Source IP**: 192.168.1.*
- **Direction**: BOTH

## Configuration File Format

Rules are saved in JSON format:

```json
[
  {
    "name": "Allow HTTPS",
    "action": "ALLOW",
    "protocol": "TCP",
    "src_ip": "ANY",
    "src_port": "ANY",
    "dst_ip": "ANY",
    "dst_port": "443",
    "direction": "OUTBOUND",
    "enabled": true
  }
]
```

## Architecture

The firewall consists of three main components:

1. **FirewallRule**: Represents individual filtering rules with matching logic
2. **FirewallEngine**: Core engine that evaluates packets against rules
3. **FirewallGUI**: User interface for managing rules and monitoring traffic

### Current Implementation

This prototype uses **simulated traffic** for demonstration purposes. The simulation generates random packets to showcase the firewall's filtering capabilities.

### Production Deployment

For real packet interception on Windows, you would need to:

1. **Install WinDivert or PyDivert**:
```bash
pip install pydivert
```

2. **Implement packet capture**: Replace the simulation with actual packet interception
3. **Run with Administrator privileges**: Required for low-level network access
4. **Add packet parsing**: Use libraries like `scapy` for detailed packet analysis

Example integration with PyDivert:
```python
import pydivert

with pydivert.WinDivert("true") as w:
    for packet in w:
        packet_info = parse_packet(packet)
        action = engine.evaluate_packet(packet_info)
        if action == "ALLOW":
            w.send(packet)
        # BLOCK: don't send, packet is dropped
```

## Limitations

- **Prototype Status**: This is an educational prototype, not production-ready
- **Simulated Traffic**: Uses simulated packets instead of real network traffic
- **No Deep Packet Inspection**: Does not analyze packet contents
- **Basic Pattern Matching**: Limited to IP/port matching
- **Windows Only**: Designed specifically for Windows platform

## Security Considerations

⚠️ **Important**: This is a learning tool and should not be used as a primary security solution. For production environments, use:

- Windows Defender Firewall
- Enterprise firewall solutions
- Professional network security appliances

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Roadmap

- [ ] Integration with WinDivert for real packet capture
- [ ] Deep packet inspection capabilities
- [ ] Intrusion detection system (IDS) features
- [ ] Machine learning-based threat detection
- [ ] Network traffic visualization
- [ ] Export logs to various formats (CSV, JSON, Syslog)
- [ ] Email/SMS alerting system
- [ ] Web-based dashboard (Django integration)
- [ ] Support for rule templates
- [ ] Geolocation-based filtering

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Python and Tkinter
- Inspired by various open-source firewall projects
- Thanks to the network security community

## Disclaimer

This software is provided for educational purposes only. The author is not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before monitoring or filtering network traffic.

## Contact

- GitHub: [@Rikiza89](https://github.com/Rikiza89)

## Support

If you find this project helpful, please consider giving it a ⭐️!
