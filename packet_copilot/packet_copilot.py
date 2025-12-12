import os
import json
import time
import logging
import subprocess

import streamlit as st
from dotenv import load_dotenv
from google import genai
from google.genai import types

# ======================================================================
# ENV + LOGGING
# ======================================================================
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PacketCopilot")

st.set_page_config(
    page_title="Selector Packet Copilot — Gemini Native",
    page_icon="🔍",
    layout="centered",
)

if not GOOGLE_API_KEY:
    st.error("❌ GOOGLE_API_KEY not set.")
    st.stop()

# ======================================================================
# GEMINI CLIENT
# ======================================================================
def get_gemini_client():
    return genai.Client(api_key=GOOGLE_API_KEY)

# ======================================================================
# SYSTEM PROMPT
# ======================================================================
def returnSystemText(pcap_data: str) -> str:
    PACKET_WHISPERER = f"""
        You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided packet_capture_info to answer user questions accurately. When a specific application layer protocol is referenced, inspect the packet_capture_info according to these hints. Format your responses in markdown with line breaks, bullet points, and appropriate emojis to enhance readability.

        **Protocol Hints:**
        - 🌐 **HTTP**: `tcp.port == 80`
        - 🔐 **HTTPS**: `tcp.port == 443`
        - 🛠 **SNMP**: `udp.port == 161` or `udp.port == 162`
        - ⏲ **NTP**: `udp.port == 123`
        - 📁 **FTP**: `tcp.port == 21`
        - 🔒 **SSH**: `tcp.port == 22`
        - 🔄 **BGP**: `tcp.port == 179`
        - 🌐 **OSPF**: IP protocol 89 (works directly on IP, no TCP/UDP)
        - 🔍 **DNS**: `udp.port == 53` (or `tcp.port == 53` for larger queries/zone transfers)
        - 💻 **DHCP**: `udp.port == 67` (server), `udp.port == 68` (client)
        - 📧 **SMTP**: `tcp.port == 25` (email sending)
        - 📬 **POP3**: `tcp.port == 110` (email retrieval)
        - 📥 **IMAP**: `tcp.port == 143` (advanced email retrieval)
        - 🔒 **LDAPS**: `tcp.port == 636` (secure LDAP)
        - 📞 **SIP**: `tcp.port == 5060` or `udp.port == 5060` (for multimedia sessions)
        - 🎥 **RTP**: No fixed port, commonly used with SIP for multimedia streams.
        - 🖥 **Telnet**: `tcp.port == 23`
        - 📂 **TFTP**: `udp.port == 69`
        - 💾 **SMB**: `tcp.port == 445` (Server Message Block)
        - 🌍 **RDP**: `tcp.port == 3389` (Remote Desktop Protocol)
        - 📡 **SNTP**: `udp.port == 123` (Simple Network Time Protocol)
        - 🔄 **RIP**: `udp.port == 520` (Routing Information Protocol)
        - 🌉 **MPLS**: IP protocol 137 (Multi-Protocol Label Switching)
        - 🔗 **EIGRP**: IP protocol 88 (Enhanced Interior Gateway Routing Protocol)
        - 🖧 **L2TP**: `udp.port == 1701` (Layer 2 Tunneling Protocol)
        - 💼 **PPTP**: `tcp.port == 1723` (Point-to-Point Tunneling Protocol)
        - 🔌 **Telnet**: `tcp.port == 23` (Unencrypted remote access)
        - 🛡 **Kerberos**: `tcp.port == 88` (Authentication protocol)
        - 🖥 **VNC**: `tcp.port == 5900` (Virtual Network Computing)
        - 🌐 **LDAP**: `tcp.port == 389` (Lightweight Directory Access Protocol)
        - 📡 **NNTP**: `tcp.port == 119` (Network News Transfer Protocol)
        - 📠 **RSYNC**: `tcp.port == 873` (Remote file sync)
        - 📡 **ICMP**: IP protocol 1 (Internet Control Message Protocol, no port)
        - 🌐 **GRE**: IP protocol 47 (Generic Routing Encapsulation, no port)
        - 📶 **IKE**: `udp.port == 500` (Internet Key Exchange for VPNs)
        - 🔐 **ISAKMP**: `udp.port == 4500` (for VPN traversal)
        - 🛠 **Syslog**: `udp.port == 514`
        - 🖨 **IPP**: `tcp.port == 631` (Internet Printing Protocol)
        - 📡 **RADIUS**: `udp.port == 1812` (Authentication), `udp.port == 1813` (Accounting)
        - 💬 **XMPP**: `tcp.port == 5222` (Extensible Messaging and Presence Protocol)
        - 🖧 **Bittorrent**: `tcp.port == 6881-6889` (File-sharing protocol)
        - 🔑 **OpenVPN**: `udp.port == 1194`
        - 🖧 **NFS**: `tcp.port == 2049` (Network File System)
        - 🔗 **Quic**: `udp.port == 443` (UDP-based transport protocol)
        - 🌉 **STUN**: `udp.port == 3478` (Session Traversal Utilities for NAT)
        - 🛡 **ESP**: IP protocol 50 (Encapsulating Security Payload for VPNs)
        - 🛠 **LDP**: `tcp.port == 646` (Label Distribution Protocol for MPLS)
        - 🌐 **HTTP/2**: `tcp.port == 8080` (Alternate HTTP port)
        - 📁 **SCP**: `tcp.port == 22` (Secure file transfer over SSH)
        - 🔗 **GTP-C**: `udp.port == 2123` (GPRS Tunneling Protocol Control)
        - 📶 **GTP-U**: `udp.port == 2152` (GPRS Tunneling Protocol User)
        - 🔄 **BGP**: `tcp.port == 179` (Border Gateway Protocol)
        - 🌐 **OSPF**: IP protocol 89 (Open Shortest Path First)
        - 🔄 **RIP**: `udp.port == 520` (Routing Information Protocol)
        - 🔄 **EIGRP**: IP protocol 88 (Enhanced Interior Gateway Routing Protocol)
        - 🌉 **LDP**: `tcp.port == 646` (Label Distribution Protocol)
        - 🛰 **IS-IS**: ISO protocol 134 (Intermediate System to Intermediate System, works directly on IP)
        - 🔄 **IGMP**: IP protocol 2 (Internet Group Management Protocol, for multicast)
        - 🔄 **PIM**: IP protocol 103 (Protocol Independent Multicast)
        - 📡 **RSVP**: IP protocol 46 (Resource Reservation Protocol)
        - 🔄 **Babel**: `udp.port == 6696` (Babel routing protocol)
        - 🔄 **DVMRP**: IP protocol 2 (Distance Vector Multicast Routing Protocol)
        - 🛠 **VRRP**: `ip.protocol == 112` (Virtual Router Redundancy Protocol)
        - 📡 **HSRP**: `udp.port == 1985` (Hot Standby Router Protocol)
        - 🔄 **LISP**: `udp.port == 4341` (Locator/ID Separation Protocol)
        - 🛰 **BFD**: `udp.port == 3784` (Bidirectional Forwarding Detection)
        - 🌍 **HTTP/3**: `udp.port == 443` (Modern web traffic)
        - 🛡 **IPSec**: IP protocol 50 (ESP), IP protocol 51 (AH)
        - 📡 **L2TPv3**: `udp.port == 1701` (Layer 2 Tunneling Protocol)
        - 🛰 **MPLS**: IP protocol 137 (Multi-Protocol Label Switching)
        - 🔑 **IKEv2**: `udp.port == 500`, `udp.port == 4500` (Internet Key Exchange Version 2 for VPNs)
        - 🛠 **NetFlow**: `udp.port == 2055` (Flow monitoring)
        - 🌐 **CARP**: `ip.protocol == 112` (Common Address Redundancy Protocol)
        - 🌐 **SCTP**: `tcp.port == 9899` (Stream Control Transmission Protocol)
        - 🖥 **VNC**: `tcp.port == 5900-5901` (Virtual Network Computing)
        - 🌐 **WebSocket**: `tcp.port == 80` (ws), `tcp.port == 443` (wss)
        - 🔗 **NTPv4**: `udp.port == 123` (Network Time Protocol version 4)
        - 📞 **MGCP**: `udp.port == 2427` (Media Gateway Control Protocol)
        - 🔐 **FTPS**: `tcp.port == 990` (File Transfer Protocol Secure)
        - 📡 **SNMPv3**: `udp.port == 162` (Simple Network Management Protocol version 3)
        - 🔄 **VXLAN**: `udp.port == 4789` (Virtual Extensible LAN)
        - 📞 **H.323**: `tcp.port == 1720` (Multimedia communications protocol)
        - 🔄 **Zebra**: `tcp.port == 2601` (Zebra routing daemon control)
        - 🔄 **LACP**: `udp.port == 646` (Link Aggregation Control Protocol)
        - 📡 **SFlow**: `udp.port == 6343` (SFlow traffic monitoring)
        - 🔒 **OCSP**: `tcp.port == 80` (Online Certificate Status Protocol)
        - 🌐 **RTSP**: `tcp.port == 554` (Real-Time Streaming Protocol)
        - 🔄 **RIPv2**: `udp.port == 521` (Routing Information Protocol version 2)
        - 🌐 **GRE**: IP protocol 47 (Generic Routing Encapsulation)
        - 🌐 **L2F**: `tcp.port == 1701` (Layer 2 Forwarding Protocol)
        - 🌐 **RSTP**: No port (Rapid Spanning Tree Protocol, L2 protocol)
        - 📞 **RTCP**: Dynamic ports (Real-time Transport Control Protocol)

        **Additional Info:**
        - Include context about traffic patterns (e.g., latency, packet loss).
        - Use protocol hints when analyzing traffic to provide clear explanations of findings.
        - Highlight significant events or anomalies in the packet capture based on the protocols.
        - Identify source and destination IP addresses
        - Identify source and destination MAC addresses
        - Look for dropped packets; loss; jitter; congestion; errors; or faults and surface these issues to the user

        Your goal is to provide a clear, concise, and accurate analysis of the packet capture data, leveraging the protocol hints and packet details.
    """
    return PACKET_WHISPERER

PACKET_WHISPERER = returnSystemText("packet_capture_info")

# ======================================================================
# PCAP → JSON CONVERSION (with payload scrubbing)
# ======================================================================
def pcap_to_json(pcap_path: str, json_path: str):
    """Run tshark to convert PCAP → JSON and scrub sensitive payloads."""
    cmd = f'tshark -nlr "{pcap_path}" -T json > "{json_path}"'
    subprocess.run(cmd, shell=True, check=True)

    try:
        with open(json_path, "r") as f:
            data = json.load(f)

        for pkt in data:
            layers = pkt.get("_source", {}).get("layers", {})

            # Remove UDP/TCP hex payloads
            udp = layers.get("udp", {})
            if isinstance(udp, dict):
                udp.pop("udp.payload", None)

            tcp = layers.get("tcp", {})
            if isinstance(tcp, dict):
                for field in [
                    "tcp.payload",
                    "tcp.segment_data",
                    "tcp.reassembled.data",
                ]:
                    tcp.pop(field, None)

            tls = layers.get("tls", {})
            if isinstance(tls, dict):
                tls.pop("tls.segment.data", None)

                # extra TLS random_bytes cleanup (optional)
                rec = tls.get("tls.record")
                if isinstance(rec, list):
                    for r in rec:
                        if not isinstance(r, dict):
                            continue
                        hs = r.get("tls.handshake", {})
                        if isinstance(hs, dict):
                            tree = hs.get("tls.handshake.random_tree", {})
                            if isinstance(tree, dict):
                                tree.pop("tls.handshake.random_bytes", None)
                elif isinstance(rec, dict):
                    hs = rec.get("tls.handshake", {})
                    if isinstance(hs, dict):
                        tree = hs.get("tls.handshake.random_tree", {})
                        if isinstance(tree, dict):
                            tree.pop("tls.handshake.random_bytes", None)

        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

    except Exception as e:
        st.error(f"JSON cleanup error: {e}")
        raise

# ======================================================================
# JSON → TOON CONVERSION (shim)
# ======================================================================
def json_to_toon(src_json: str) -> str:
    """
    Convert a JSON file into TOON format using toon-format (preferred)
    or npx @toon-format/cli as a fallback.

    If both commands fail, we fall back to the original JSON so the app
    still works, but log a warning.
    """
    base, ext = os.path.splitext(src_json)
    toon_path = f"{base}.toon.json"

    try_cmds = [
        ["toon-format", src_json, "-o", toon_path],
        ["npx", "@toon-format/cli", src_json, "-o", toon_path],
    ]

    last_err = None
    for cmd in try_cmds:
        try:
            logger.info(f"🎨 Running TOON conversion: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            logger.info(f"✅ TOON created at: {toon_path}")
            return toon_path
        except Exception as e:
            last_err = e
            logger.warning(f"TOON conversion failed with {cmd[0]}: {e}")

    # If we get here, both commands failed
    logger.warning(
        f"⚠️ TOON conversion failed with all commands; "
        f"falling back to original JSON: {src_json}"
    )
    return src_json

# ======================================================================
# FILE SEARCH STORE HANDLING
# ======================================================================
def upload_json_to_file_search(json_path: str) -> str:
    """
    Create a File Search store and upload the PCAP JSON to it.
    IMPORTANT: we upload the JSON, not the PCAP.
    """
    client = get_gemini_client()

    display = f"pcap_store_{int(time.time())}"
    store = client.file_search_stores.create(
        config={"display_name": display}
    )
    store_name = store.name
    logger.info(f"📁 Created FileSearchStore: {store_name}")

    operation = client.file_search_stores.upload_to_file_search_store(
        file_search_store_name=store_name,
        file=json_path,
    )

    while not operation.done:
        time.sleep(1)
        operation = client.operations.get(operation)

    return store_name

def delete_file_search_store(store_name: str):
    try:
        client = get_gemini_client()
        client.file_search_stores.delete(name=store_name)
        logger.info(f"🗑 Deleted FileSearchStore: {store_name}")
    except Exception as e:
        logger.warning(f"Error deleting store: {e}")

# ======================================================================
# GEMINI QUERY (File Search + System Prompt)
# ======================================================================
def query_gemini(store_name: str, chat_history: list, user_question: str):
    client = get_gemini_client()

    tool = types.Tool(
        file_search=types.FileSearch(
            file_search_store_names=[store_name]
        )
    )

    contents = []
    for msg in chat_history:
        role = "user" if msg["role"] == "user" else "model"
        contents.append(
            types.Content(
                role=role,
                parts=[types.Part(text=msg["content"])],
            )
        )

    contents.append(
        types.Content(
            role="user",
            parts=[types.Part(text=user_question)],
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
    return resp

# ======================================================================
# SESSION STATE
# ======================================================================
def init_state():
    st.session_state.setdefault("messages", [])
    st.session_state.setdefault("store_name", None)
    st.session_state.setdefault("json_path", None)
    st.session_state.setdefault("uploaded_file_name", None)
    st.session_state.setdefault("num_packets", 0)

def reset_session():
    if st.session_state.store_name:
        delete_file_search_store(st.session_state.store_name)

    for k in [
        "messages",
        "store_name",
        "json_path",
        "uploaded_file_name",
        "num_packets",
    ]:
        st.session_state[k] = None

    st.session_state.messages = []

    st.rerun()

# ======================================================================
# UI SECTIONS
# ======================================================================
def show_header():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(script_dir, "logo.jpeg")

    if os.path.exists(logo_path):
        st.image(logo_path)

    st.markdown("---")
    st.write("Welcome to Selector Packet Copilot — now powered by Gemini File Search.")
    st.markdown("---")

def show_how_to_use():
    st.write("### How to Use the Tool:")
    st.write(
        """
1. **Upload a PCAP File** (max ~5 MB).
2. The app converts it to JSON and indexes it into **Gemini File Search**.
3. Use the chat to ask natural language questions about the capture.
        """
    )
    st.markdown("---")

def show_disclaimer():
    st.write(
        """
**Data handling & safety**

- PCAP → JSON → File Search data are used only for this analysis flow.
- Follow your enterprise AI governance before uploading sensitive captures.
        """
    )
    st.markdown("---")

def show_mcp_section():
    st.markdown("## 🆕 MCP access to Packet Copilot")
    st.write(
        """
Packet Copilot also exposes an MCP endpoint, so you can use it from  
**Claude Desktop**, **Gemini CLI**, or **VS Code (Copilot)**.
        """
    )
    base_json = """{
  "mcpServers": {
    "PacketCopilot": {
      "httpUrl": "https://packetcopilot.selector.ai/mcp/"
    }
  }
}"""
    st.code(base_json, language="json")

    with st.expander("Claude Desktop config"):
        st.code(base_json, language="json")

    with st.expander("Gemini CLI config"):
        st.code(base_json, language="json")

    with st.expander("VS Code (Copilot) config"):
        st.code(base_json, language="json")

    st.markdown("---")

def show_sample_pcaps():
    st.write("### Sample Packet Captures for Testing")

    pcap_dir = os.path.join(os.path.dirname(__file__), "pcap")

    pcaps = {
        "BGP Sample": os.path.join(pcap_dir, "bgp.pcap"),
        "Capture Sample (Single Packet)": os.path.join(pcap_dir, "capture.pcap"),
        "DHCP Sample": os.path.join(pcap_dir, "dhcp.pcap"),
        "EIGRP Sample": os.path.join(pcap_dir, "eigrp.pcap"),
        "VXLAN Sample": os.path.join(pcap_dir, "vxlan.pcapng"),
        "Slammer Worm Sample": os.path.join(pcap_dir, "slammer.pcap"),
        "Teardrop Attack Sample": os.path.join(pcap_dir, "teardrop.pcap"),
    }

    for name, filepath in pcaps.items():
        try:
            with open(filepath, "rb") as f:
                st.download_button(
                    label=name,
                    data=f,
                    file_name=os.path.basename(filepath),
                    mime="application/vnd.tcpdump.pcap",
                )
        except FileNotFoundError:
            st.warning(f"Sample not found on server: {name}")

    st.markdown("---")

def show_selector_iframe():
    selector_ai_demo_url = "https://www.selector.ai/request-a-demo/"
    try:
        st.components.v1.html(
            f'<iframe src="{selector_ai_demo_url}" '
            'width="100%" height="800" frameborder="0"></iframe>',
            height=800,
        )
    except Exception:
        st.warning("Unable to display the Selector AI website inside the app.")
        st.write("For more information, visit [Selector.ai](https://selector.ai).")

def show_footer():
    st.markdown("---")
    st.write("Selector AI — Packet Copilot")
    st.markdown("---")

# ======================================================================
# CORE FLOW: Upload + Process PCAP
# ======================================================================
def upload_and_process_pcap():
    uploaded = st.file_uploader(
        "Upload PCAP / PCAPNG",
        type=["pcap", "pcapng"],
        help="Limit ~5 MB per file",
    )
    if not uploaded:
        return

    MAX_MB = 5
    if uploaded.size > MAX_MB * 1024 * 1024:
        st.error(f"Max file size {MAX_MB}MB")
        return

    temp_dir = "temp_pcap"
    os.makedirs(temp_dir, exist_ok=True)
    pcap_path = os.path.join(temp_dir, uploaded.name)
    json_path = pcap_path + ".json"

    with open(pcap_path, "wb") as f:
        f.write(uploaded.getvalue())

    try:
        with st.spinner("Converting PCAP → JSON…"):
            pcap_to_json(pcap_path, json_path)

        # ✅ NEW: JSON → TOON
        with st.spinner("Converting JSON → TOON…"):
            index_path = json_to_toon(json_path)

        with st.spinner("Indexing TOON into Gemini File Search…"):
            store = upload_json_to_file_search(index_path)

        # Keep original JSON path in case you ever need it
        st.session_state.store_name = store
        st.session_state.json_path = json_path
        st.session_state.uploaded_file_name = uploaded.name

        # If you still want this, compute num_packets off the original JSON
        try:
            with open(json_path, "r") as f:
                st.session_state.num_packets = len(json.load(f))
        except Exception as e:
            logger.warning(f"Could not compute num_packets: {e}")
            st.session_state.num_packets = 0

        st.success("✅ PCAP successfully processed, TOON-ified, and indexed!")
        st.rerun()

    except Exception as e:
        st.error(f"Processing failed: {e}")

    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
        # We keep json_path (and toon file) for debugging / reuse if needed

# ======================================================================
# CHAT UI (File Search + Gemini)
# ======================================================================
def show_chat_ui():
    st.markdown("---")
    st.subheader("Ask a question about the PCAP")

    # Show history
    for m in st.session_state.messages:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])

    question = st.chat_input("Ask Packet Copilot…")
    if not question:
        return

    # Store user message
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        placeholder = st.empty()
        placeholder.markdown("Analyzing packets with Gemini…")

        try:
            resp = query_gemini(
                st.session_state.store_name,
                st.session_state.messages[:-1],
                question,
            )
            text = resp.text
            placeholder.markdown(text)
            st.session_state.messages.append(
                {"role": "assistant", "content": text}
            )
        except Exception as e:
            placeholder.error(str(e))

# ======================================================================
# MAIN
# ======================================================================
def main():
    init_state()

    show_header()
    show_how_to_use()
    show_disclaimer()
    show_mcp_section()
    show_sample_pcaps()

    st.markdown("---")

    if not st.session_state.store_name:
        upload_and_process_pcap()
    else:
        if st.button("Reset / Clear Session"):
            reset_session()
        show_chat_ui()

    st.markdown("---")
    show_selector_iframe()
    show_footer()

if __name__ == "__main__":
    main()
