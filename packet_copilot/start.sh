#!/bin/bash
# Start MCP server in background
python3 packet_copilot/mcp_server.py &
# Start Streamlit in foreground
exec streamlit run packet_copilot/packet_copilot.py --server.port=8501
