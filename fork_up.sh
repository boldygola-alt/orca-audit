#!/usr/bin/env bash
# Re-provision the fork after the sandbox reset: install surfpool, start a mainnet fork,
# fund the fresh session actor, and report identity + slot. Never touches mainnet.
set -uo pipefail
cd /home/user
if [ ! -x tools/surfpool ]; then
  mkdir -p tools
  curl -sL -m 300 -o /tmp/surfpool.tar.gz \
    https://github.com/solana-foundation/surfpool/releases/latest/download/surfpool-linux-x64.tar.gz
  tar xzf /tmp/surfpool.tar.gz -C /tmp && find /tmp -maxdepth 3 -name surfpool -type f -exec mv {} /home/user/tools/surfpool \;
  chmod +x /home/user/tools/surfpool
fi
/home/user/tools/surfpool --version || exit 1
nohup /home/user/tools/surfpool start --rpc-url https://api.mainnet-beta.solana.com \
  -p 8899 --ws-port 8900 --no-tui \
  -k /home/user/orca-audit/keys/actor_session2.json \
  --airdrop 4LWptHzEFd85eL3nEn1bPK3h4RZzL6Sfi4N96ZdpYZ5f --airdrop-amount 500000000000000000 \
  > /home/user/orca-audit/surfpool_session3.log 2>&1 &
for i in $(seq 1 60); do
  sleep 2
  h=$(curl -s -m 5 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth","params":[]}' http://127.0.0.1:8899)
  if echo "$h" | grep -q '"ok"'; then
    s=$(curl -s -m 5 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[]}' http://127.0.0.1:8899)
    echo "FORK READY health=$h slot=$s"
    exit 0
  fi
done
echo "FORK FAILED TO START"; tail -20 /home/user/orca-audit/surfpool_session3.log; exit 1
