#!/usr/bin/env bash
# Session-4 fork: mainnet fork + --skip-blockhash-check so that *verbatim* historical
# (third-party-signed) transactions can be replayed without re-signing.  Signature
# verification is left ENABLED (never --skip-signature-verification).
set -uo pipefail
cd /home/user
pkill -f "surfpool start" 2>/dev/null; sleep 1
[ -x tools/surfpool ] || { echo "surfpool missing"; exit 1; }
tools/surfpool --version
nohup tools/surfpool start --rpc-url https://api.mainnet-beta.solana.com \
  -p 8899 --ws-port 8900 --no-tui --host 0.0.0.0 \
  --skip-blockhash-check \
  -k /home/user/orca-audit/keys/actor_session2.json \
  --airdrop 4LWptHzEFd85eL3nEn1bPK3h4RZzL6Sfi4N96ZdpYZ5f --airdrop-amount 500000000000000000 \
  > /home/user/orca-audit/surfpool_session4.log 2>&1 &
for i in $(seq 1 90); do
  sleep 2
  h=$(curl -s -m 5 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth","params":[]}' http://127.0.0.1:8899)
  if echo "$h" | grep -q '"ok"'; then
    s=$(curl -s -m 5 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[]}' http://127.0.0.1:8899)
    echo "FORK READY health=$h slot=$s"; exit 0
  fi
done
echo "FORK FAILED TO START"; tail -20 /home/user/orca-audit/surfpool_session4.log; exit 1
