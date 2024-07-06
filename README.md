# a-SSH-at

A simple SSH honeypot server to farm IPs, usernames and passwords of unsolicited login/bruteforce attempts. Data is logged to a JSON file.

Inspired by https://github.com/internetwache/SSH-Honeypot

## Usage

Requires a reasonably modern Python version.

It's recommended to set up port forwarding to avoid having to run the script as root: `iptables -A PREROUTING -t nat -p tcp --dport 22 -j REDIRECT --to-port 2222`.

1. Create and activate venv: `python3 -m venv .venv && source .venv/bin/activate`
2. Install requirements: `pip install -r requirements.txt`
3. Start the server: `./sshpot.py`

## Options

- `--port` (default `2222`): which port to listen on for incoming SSH connections
- `--workers` (default `8`): how many worker threads to use for request processing
- `--output` (default `asshats.json`): json database file to log collected data

## Future ideas

- Add an option to actually let attackers connect and log which commands they'll try to execute
- 
