#!/bin/bash
mkdir -p /tmp/test-ls
cd /tmp/test-ls
echo '{"dependencies": {"express": "4.17.1"}}' > package.json
npm install --package-lock-only --ignore-scripts
npm ls qs --json --all
