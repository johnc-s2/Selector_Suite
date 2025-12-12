import os
import base64
import json
import uuid
import subprocess
import tempfile
import shutil
import logging
import time

from collections import defaultdict
from typing import Any, Dict, List

from dotenv import load_dotenv
from fastmcp import FastMCP

from google import genai
from google.genai import types

# ================================================================
# ENV + LOGGING
# ================================================================
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
assert GOOGLE_API_KEY, "Missing GOOGLE_API_KEY"

logger = logging.getLogger("PacketCopilotMCP")
logging.basicConfig(level=logging.INFO)


# ================================================================
# GEMINI CLIENT
# ================================================================
def gemini() -> genai.Client:
    return genai.Client(api_key=GOOGLE_API_KEY)


# ================================================================
# SYSTEM PROMPT
# ================================================================
PACKET_WHISPERER = """
You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis.
Use the data in the provided packet_capture_info to answer user questions accurately.
When a specific application layer protocol is referenced, inspect the packet_capture_info according to these hints.
Format your responses in markdown with line breaks, bullet points, and appropriate emojis to enhance readability.

🌍 Geolocation Handling
- If a public IP appears in the data, AI lookup results will be included before you answer.
- Do NOT estimate IP locations yourself—use the provided geolocation data.

Protocol Hints (examples):
- HTTP: tcp.port == 80
- HTTPS: tcp.port == 443
- SNMP: udp.port == 161 or udp.port == 162
- NTP: udp.port == 123
- FTP: tcp.port == 21
- SSH: tcp.port == 22
- BGP: tcp.port == 179
- OSPF: IP protocol 89 (no TCP/UDP)
- DNS: udp.port == 53 (or tcp.port == 53)
- DHCP: udp.port == 67 / 68
- SMTP: tcp.port == 25
- POP3: tcp.port == 110
- IMAP: tcp.port == 143
- LDAPS: tcp.port == 636
- SIP: tcp.port == 5060 or udp.port == 5060
- RTP: dynamic UDP ports, usually with SIP
- Telnet: tcp.port == 23
- TFTP: udp.port == 69
- SMB: tcp.port == 445
- RDP: tcp.port == 3389
- VXLAN: udp.port == 4789
- NetFlow: udp.port == 2055
- L2TP: udp.port == 1701
- IPsec ESP: IP protocol 50
- IPsec AH: IP protocol 51
- Many other routing / VPN / monitoring protocols as in your full hint list.

Additional Info:
- Include context about traffic patterns (latency, packet loss, retransmissions, resets).
- Use protocol hints when analyzing traffic to provide clear explanations of findings.
- Highlight significant events or anomalies in the packet capture based on the protocols.
- Identify source and destination IP addresses.
- Identify source and destination MAC addresses when available.
- Look for dropped packets, loss, jitter, congestion, errors, or faults and surface these issues to the user.

Your goal is to provide a clear, concise, and accurate analysis of the packet capture data,
leveraging the protocol hints and packet details.
"""


# ================================================================
# MCP SERVER
# ================================================================
mcp = FastMCP("PacketCopilot", streamable_http_path="/mcp/")

# session_id → store { dir, pcap_path, json_path, store_name }
SESSIONS: Dict[str, Dict[str, Any]] = defaultdict(dict)


def session(session_id: str) -> Dict[str, Any]:
    """Return or initialize a session dict."""
    s = SESSIONS[session_id]
    if "dir" not in s:
        s["dir"] = tempfile.mkdtemp(prefix=f"pcap_{session_id}_")
    return s


# ================================================================
# PCAP → JSON
# ================================================================
def pcap_to_json(in_path: str, out_path: str) -> None:
    """Run tshark to convert PCAP → JSON and scrub some payload fields."""
    cmd = f'tshark -nlr "{in_path}" -T json > "{out_path}"'
    subprocess.run(cmd, shell=True, check=True)

    with open(out_path, "r") as f:
        data = json.load(f)

    # Basic scrubbing of heavy / sensitive payload fields
    for pkt in data:
        layers = pkt.get("_source", {}).get("layers", {})

        tcp = layers.get("tcp", {})
        if isinstance(tcp, dict):
            tcp.pop("tcp.payload", None)
            tcp.pop("tcp.segment_data", None)
            tcp.pop("tcp.reassembled.data", None)

        udp = layers.get("udp", {})
        if isinstance(udp, dict):
            udp.pop("udp.payload", None)

        tls = layers.get("tls", {})
        if isinstance(tls, dict):
            tls.pop("tls.segment.data", None)

    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)


# ================================================================
# FILE SEARCH: CREATE / UPLOAD / DELETE
# ================================================================
def create_store() -> str:
    client = gemini()
    display = f"pcap_store_{int(time.time())}"
    store = client.file_search_stores.create(
        config={"display_name": display}
    )
    return store.name


def upload_to_store(store_name: str, json_path: str) -> None:
    """
    Upload the sanitized JSON to a File Search store.

    IMPORTANT: we do NOT pass a mime_type here; the backend will infer
    it from the .json extension, avoiding the INVALID_ARGUMENT error.
    """
    client = gemini()
    client.file_search_stores.upload_to_file_search_store(
        file_search_store_name=store_name,
        file=json_path,
    )


def delete_store(store_name: str) -> None:
    try:
        gemini().file_search_stores.delete(name=store_name)
        logger.info(f"Deleted File Search store: {store_name}")
    except Exception as e:
        logger.error(f"Failed to delete File Search store: {e}")


# ================================================================
# GEMINI + FILE SEARCH QUERY
# ================================================================
def query_file_search(
    store_name: str,
    user_content: str,
    history: List[Dict[str, str]],
) -> str:
    client = gemini()

    tool = types.Tool(
        file_search=types.FileSearch(
            file_search_store_names=[store_name]
        )
    )

    contents: List[types.Content] = []

    # History is expected as [{"role": "user"|"assistant", "content": "..."}]
    for msg in history:
        role = "user" if msg.get("role") == "user" else "model"
        contents.append(
            types.Content(
                role=role,
                parts=[types.Part(text=msg.get("content", ""))],
            )
        )

    contents.append(
        types.Content(
            role="user",
            parts=[types.Part(text=user_content)],
        )
    )

    resp = client.models.generate_content(
        model="gemini-3-pro-preview",
        contents=contents,
        config=types.GenerateContentConfig(
            tools=[tool],
            system_instruction=PACKET_WHISPERER,
            temperature=0.3,
        ),
    )
    return resp.text


# ================================================================
# MCP TOOLS
# ================================================================
@mcp.tool
def new_session() -> str:
    """Start a new Packet Copilot session."""
    sid = str(uuid.uuid4())
    session(sid)
    logger.info(f"New PacketCopilot session: {sid}")
    return sid


@mcp.tool
def upload_pcap_base64(session_id: str, filename: str, b64: str) -> str:
    """
    Upload a PCAP file into a given session.

    Args:
        session_id: ID returned by new_session
        filename: filename to write on disk (e.g., capture.pcap)
        b64: base64-encoded binary PCAP contents
    """
    s = session(session_id)
    raw = base64.b64decode(b64)
    pcap_path = os.path.join(s["dir"], filename)

    with open(pcap_path, "wb") as f:
        f.write(raw)

    s["pcap_path"] = pcap_path
    logger.info(f"[{session_id}] Uploaded PCAP to {pcap_path}")
    return pcap_path


@mcp.tool
def convert_to_json(session_id: str) -> str:
    """Convert PCAP → JSON for the given session."""
    s = session(session_id)
    if "pcap_path" not in s:
        raise ValueError("Upload PCAP first (upload_pcap_base64).")

    json_path = s["pcap_path"] + ".json"
    pcap_to_json(s["pcap_path"], json_path)
    s["json_path"] = json_path

    logger.info(f"[{session_id}] Converted PCAP to JSON at {json_path}")
    return json_path


@mcp.tool
def index_pcap(session_id: str) -> str:
    """
    Create a File Search store & upload sanitized JSON.

    Must be called after convert_to_json.
    """
    s = session(session_id)
    if "json_path" not in s:
        raise ValueError("convert_to_json must be called first.")

    store = create_store()
    s["store_name"] = store

    upload_to_store(store, s["json_path"])

    logger.info(f"[{session_id}] File Search store created: {store}")
    return store


@mcp.tool
def analyze_pcap(
    session_id: str,
    question: str,
    history: List[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Analyze the indexed PCAP with Gemini + File Search.

    Args:
        session_id: ID returned by new_session
        question: natural language question about the capture
        history: optional chat history for context
    """
    s = SESSIONS.get(session_id)
    if not s:
        return {"error": "Unknown session_id. Call new_session first."}

    store_name = s.get("store_name")
    if not store_name:
        return {"error": "Must call index_pcap first."}

    history = history or []

    logger.info(f"[{session_id}] Analyzing PCAP with question: {question!r}")
    answer = query_file_search(
        store_name=store_name,
        user_content=question,
        history=history,
    )
    return {"answer": answer}


@mcp.tool
def cleanup(session_id: str) -> str:
    """
    Delete all session resources & File Search store.

    Safe to call multiple times.
    """
    s = SESSIONS.pop(session_id, None)

    if s:
        if s.get("store_name"):
            delete_store(s["store_name"])
        if s.get("dir") and os.path.exists(s["dir"]):
            shutil.rmtree(s["dir"], ignore_errors=True)

    logger.info(f"[{session_id}] Cleanup complete")
    return "ok"


# ================================================================
# ENTRYPOINT
# ================================================================
if __name__ == "__main__":
    # HTTP transport so you can point Claude / Gemini CLI / Continue at it.
    mcp.run(transport="http", host="0.0.0.0", port=8000)
