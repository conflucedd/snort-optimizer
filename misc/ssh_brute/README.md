# SSH Brute Force Attack Module for Snort Testing

This Go module generates SSH brute force login attempts to trigger Snort alerts.

## Prerequisites

- Go 1.21 or later
- Snort 3.x with SSH brute force detection rules enabled
- SSH server running on port 22 (localhost)

## Configuration

The target IP is hardcoded as `192.168.1.3:22`. The source IP is bound to `192.168.1.175` (secondary IP on enp11s0). Adjust these addresses in `simple_attack.go` if needed.

## Usage

1. **Start Snort** in the parent directory:
   ```bash
   cd /home/c/snort-optimizer/traffic_gen
   ./start_snort.sh
   ```
   Wait about 20 seconds for Snort to initialize.

2. **Run the attack**:
   ```bash
   go run simple_attack.go
   ```
   Or build and run:
   ```bash
   go build -o simple_attack simple_attack.go
   ./simple_attack
   ```

3. **Check alerts**:
   - `alert_fast.txt` and `alert_json.txt` in the parent directory should contain entries for "INDICATOR-SCAN SSH brute force login attempt".

## Custom Snort Rule

A custom rule `config/ssh_brute.rules` is included with lowered threshold (2 attempts in 60 seconds). The main `config/snort.lua` has been modified to include this rule. If you need to reset the configuration, restore the original `snort.lua`.

## Attack Details

The attack performs 10 TCP connections to port 22, sending the SSH protocol identification string `SSH-2.0-GoClient\r\n` and immediately closing the connection. This triggers Snort's SSH brute force detection rule (sid 19559).

## Notes

- Ensure the SSH server is running on port 22.
- The attack uses a secondary IP as source to appear as external traffic.
- Snort must be monitoring interface `enp11s0`.
- To clear alerts, kill Snort and restart (the startup script deletes alert files).

## Files

- `simple_attack.go` - Main attack program
- `main.go` - Original SSH client attack (full handshake)
- `go.mod`, `go.sum` - Go module dependencies
- `README.md` - This file