
#!/bin/bash
pkill -f "surfpool start" 2>/dev/null; sleep 2
surfpool start --no-tui --ci -p 8899 --ws-port 8900 --host 0.0.0.0 --rpc-url https://api.mainnet-beta.solana.com --no-studio --airdrop-keypair-path /home/user/orca-audit/tests/attacker.json --airdrop-amount 50000000000000 > /home/user/orca-audit/surfpool.log 2>&1 &
sleep 10
curl -s http://127.0.0.1:8899 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'; echo
curl -s http://127.0.0.1:8899 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":2,"method":"getBalance","params":["'$(python3 -c "import json;print(json.load(open('/home/user/orca-audit/tests/attacker.json'))['pubkey'])")'"]}'; echo

