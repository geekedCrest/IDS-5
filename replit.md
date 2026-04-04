# µIDS - Micro Intrusion Detection System

A Python-based network signature intrusion detection system.

## Project Structure

- `main.py` - Entry point; starts the Sniffer and Analyzer processes
- `sniffer.py` - Network packet capture using Scapy (multiprocessing)
- `analyzer.py` - Packet analysis and rule matching (multiprocessing)
- `signature.py` - Packet signature representation
- `rules.py` - Rule parsing and loading
- `default.rules` - Default IDS rules
- `eval.rules` - Additional evaluation rules

## Usage

```bash
sudo python3 main.py <INTERFACE> [RULE_PATH]
```

Example: `sudo python3 main.py eth0 default.rules`

## Rule Format

```
PROTO [!]IP|any:[!]PORT(RANGE)|any <>|-> [!]IP|any:[!]PORT(RANGE)|any *PAYLOAD
```

## Dependencies

- `scapy>=2.4.1` - Packet capture and analysis
- `netifaces==0.10.7` - Network interface information

## Notes

- Requires root/sudo privileges to capture raw network packets
- Logs are written to the `logs/` directory (created automatically)
- In Replit, raw packet capture requires elevated permissions not available in the sandbox

## Workflow

- **Start application** (console): Runs `python3 main.py` — exits with usage info unless a network interface is provided
