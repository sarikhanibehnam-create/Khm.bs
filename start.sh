#!/bin/bash
cd "$(dirname "$0")"
python3 server.py &
sleep 1
xdg-open http://localhost:8765 2>/dev/null || open http://localhost:8765 2>/dev/null
echo "System running on http://localhost:8765"
