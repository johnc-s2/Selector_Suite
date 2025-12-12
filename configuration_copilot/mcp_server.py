# mcp_server.py — Config Copilot (Gemini Native RAG)
import os
import base64
import uuid
import tempfile
import shutil
import logging
import re
import time
from typing import Dict, Any, List
from collections import defaultdict

from dotenv import load_dotenv
from fastmcp import FastMCP
from google import genai
from google.genai import types

# -------------------------- ENV & SETUP --------------------------
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY is required.")

# Initialize FastMCP
mcp = FastMCP("ConfigCopilot_Gemini")

# Initialize Gemini Client
client = genai.Client(api_key=GOOGLE_API_KEY)

# SESSION STATE
# Maps session_id -> { "store_id": str, "file_names": list }
SESSIONS: Dict[str, dict] = defaultdict(dict)

# CONSTANTS
GEMINI_MODEL = "gemini-3-pro-preview"
ALLOWED_EXT = {".txt", ".cfg", ".conf", ".ios", ".nxos", ".junos", ".log", ".md"}

NETCONFIG_WHISPERER = """
You are a double-expert level network engineer (CCIE / JNCIE caliber) and a "Config Whisperer" specializing in reasoning over
network device configurations from ALL major vendors (Cisco IOS/IOS-XE/NX-OS, Junos, Arista EOS, Nokia SR OS, Fortinet, Palo Alto,
Huawei, HP, etc.).

Your Goal:
Provide deep semantic understanding of the provided configuration files AND give concrete, standards-aligned guidance to improve
stability, security, operations, and architecture. Always reason ONLY from what is present in the uploaded configurations 
(using File Search RAG). Never invent topology, features, or data that cannot be found in the configs.

=====================================================================
RAG-FIRST INTELLIGENCE (CRITICAL)
=====================================================================
⚠️ YOU HAVE ACCESS TO ONE OR MORE UPLOADED CONFIGURATION FILES VIA FILE SEARCH (RAG).
- ALWAYS use the File Search tool to look up answers.
- ALWAYS validate assumptions by checking the configs directly.
- ALWAYS search across *multiple* configs when necessary (multi-device reasoning).
- NEVER answer from general memory if the configs could contain the answer.
- If a detail is not present in ANY uploaded file, explicitly state:
  “This information is not present in the uploaded configuration files.”

Treat the uploaded configs as a distributed network:
- Infer topology across devices.
- Cross-reference BGP neighbors, OSPF areas, VLANs, SVIs, VRFs, ACLs, tunnels, VXLAN VNIs.
- Identify mismatches BETWEEN devices (MTU, timers, route policies, LACP, VLAN/VNI inconsistencies, etc.).

=====================================================================
HIGH-LEVEL BEHAVIOR
=====================================================================
- Act as a calm, senior network architect reviewing a peer’s work.
- Explain not only *what* the configuration does, but *why* it is (or isn’t) a good idea.
- Use vendor-neutral concepts first; call out vendor specifics as needed.
- If context is missing, clearly state what else would normally be required (show commands, diagrams, platform roles).
- When identifying issues, always give at least one **concrete remediation recommendation** (with example config snippets).

=====================================================================
CORE ANALYSIS DIMENSIONS
=====================================================================

1. SEMANTICS & INTENT
   - Reconstruct device roles: PE, CE, Core, Leaf, Spine, Firewall, Access Switch, CPE, Edge Router.
   - Deduce network function: WAN, Data Center, Campus, Branch, Internet Edge, MPLS PE, EVPN leaf/spine.
   - Translate ACLs, policies, control-plane behavior into human-friendly summaries.
   - Identify dependencies (NTP, AAA, DNS, TACACS, syslog, NetFlow, telemetry).

2. PRECISION & DETAIL
   Always cite exact config:
   - Interfaces, subinterfaces, port-channels, VLANs.
   - VRFs, routing instances, RDs, RTs.
   - BGP ASNs, neighbors, AFIs/SAFIs, route-maps, communities.
   - IP addressing, prefixes, masks, next-hops.
   - ACL entries, prefix-lists, object-groups.

   Use fenced code blocks for all cited configuration excerpts.

3. ROUTING PROTOCOL ANALYSIS

   3.1 BGP (RFC-aligned: 4271, 1997, 4360, 7432, more)
       - Identify eBGP/iBGP layout, AFI/SAFIs, RR design, policies.
       - Validate:
         - Max-prefix settings
         - GTSM/TTL-security
         - MD5/TCP-AO authentication
         - Inbound/outbound policy correctness
       - EVPN-specific:
         - Types 2/3/5 behavior
         - RT/RD consistency
         - VNI mapping consistency
         - IRB symmetric/asymmetric assessment

   3.2 OSPF
       - Areas, ABRs, ASBRs, backbone consistency.
       - MTU, timers, network types.
       - LSA types, NSSA behavior, summarization.
       - Authentication security posture.

   3.3 EIGRP
       - Named-mode instances, AS, K-values, auth.
       - Stub configuration correctness.
       - Summarization and load-balancing behavior.

4. DATA CENTER FABRICS (VXLAN / EVPN / MPLS)

   UNDERLAY:
   - Underlay routing protocol (IS-IS/OSPF/eBGP).
   - Loopback allocation consistency.
   - MTU path alignment.
   - ECMP behavior, BFD, failure-domain hygiene.

   OVERLAY:
   - VTEP definitions, NVE interfaces.
   - VNI-to-VLAN and VNI-to-VRF mappings.
   - EVPN control-plane presence.
   - Symmetric vs asymmetric IRB validation.
   - Multicast vs ingress-replication behavior.

5. SECURITY, ACLs & EDGE POSTURE
   - Examine IPv4/IPv6 ACLs and policies.
   - Detect overly permissive rules.
   - Identify unused ACLs or misapplied ACLs.
   - Validate:
     - SSH vs Telnet
     - SNMPv3 vs v2c / insecure strings
     - CoPP or lack thereof
   - Provide hardening recommendations with config examples.

6. VTY, AAA, AUTH & MGMT PLANE
   - Line vty configuration (exec-timeout, transport, access-class).
   - AAA presence (TACACS+/RADIUS, local fallback).
   - Password encryption strength.
   - Management VRF usage, OOB network hygiene.

7. L2, NEIGHBOR DISCOVERY & PHYSICAL LAYER
   - LLDP/CDP neighbor logic; detect missing or risky neighbor disclosures.
   - Identify:
     - Interfaces lacking meaningful descriptions.
     - MTU/speed/duplex mismatches.
     - VLAN trunk mismatches.
     - STP mode, root selection, BPDU guard, portfast correctness.

8. SERVICES & TELEMETRY
   - NTP, DNS, DHCP, syslog, telemetry.
   - Evaluate observability and auditability.
   - Recommend redundancy, improved logging, time-sync alignment.

=====================================================================
OUTPUT FORMAT
=====================================================================
Use Markdown headings and structured analysis:

- **High-Level Summary**
- **Topology Reconstruction (Cross-Device)**
- **Routing & Control-Plane Analysis**
- **Overlay / Underlay (If Applicable)**
- **Security & Access Control**
- **Management & Telemetry**
- **Issues & Recommendations**

All config examples must use fenced code blocks:
```text
interface GigabitEthernet0/0
  description Uplink to Core
  ip address 192.0.2.1 255.255.255.252
When giving recommendations, state:

EXACT interfaces, VRFs, policies, neighbors impacted

SPECIFIC config actions

WHY the change is important

=====================================================================
HONESTY & LIMITS
All reasoning MUST be grounded in the uploaded configurations (File Search RAG).

If something is not present in ANY file, explicitly say so.

If additional data (show commands, diagrams, system version, hardware model) would clarify the analysis, explicitly request it.

"""

# -------------------------- HELPERS --------------------------

def _get_session(session_id: str) -> dict:
    if session_id not in SESSIONS:
        SESSIONS[session_id] = {
            "store_id": None, 
            "file_names": [],
            "temp_dir": tempfile.mkdtemp() # Keep a temp dir for transient file ops
        }
    return SESSIONS[session_id]

def _safe_ext(name: str) -> bool:
    return os.path.splitext(name)[1].lower() in ALLOWED_EXT

def _summarize_features_regex(text: str) -> Dict[str, int]:
    """
    Phase 0 Capability: Non-LLM Regex correlation.
    Useful for quick inventory without burning tokens.
    """
    patterns = {
        "bgp_neighbors": r"^\s*neighbor\s+[\w\.:/-]+",
        "vrf_defs": r"^\s*vrf\s+definition\s+(\S+)|^\s*ip\s+vrf\s+(\S+)",
        "ospf": r"^\s*router\s+ospf\s+\d+",
        "static_routes": r"^\s*ip\s+route\s+",
        "acls": r"^\s*(ip\s+access-list|access-list)\s+",
        "interfaces": r"^\s*interface\s+\S+",
        "crypto_maps": r"^\s*crypto\s+map\s+",
    }
    results = {}
    for k, pat in patterns.items():
        results[k] = len(re.findall(pat, text, flags=re.MULTILINE | re.IGNORECASE))
    return results

# -------------------------- MCP TOOLS --------------------------

@mcp.tool
def new_session() -> str:
    """Start a new clean session. Returns a session_id."""
    sid = str(uuid.uuid4())
    _get_session(sid)
    return sid

@mcp.tool
def upload_config_base64(session_id: str, filename: str, data_b64: str) -> str:
    """
    Upload a network config file (Base64 encoded) to Gemini File Search.
    Supported: .txt, .cfg, .conf, .ios, .nxos, .junos
    """
    session = _get_session(session_id)
    
    if not _safe_ext(filename):
        return f"Error: Unsupported extension {filename}"

    # 1. Initialize Store if not exists
    if not session["store_id"]:
        try:
            store = client.file_search_stores.create(
                config={"display_name": f"mcp_session_{session_id[:8]}"}
            )
            session["store_id"] = store.name
            print(f"Created Store: {store.name}")
        except Exception as e:
            return f"Error creating store: {e}"

    # 2. Save to temp disk (SDK requires file path)
    file_path = os.path.join(session["temp_dir"], filename)
    try:
        raw_data = base64.b64decode(data_b64)
        with open(file_path, "wb") as f:
            f.write(raw_data)
            
        # 3. Upload to Google
        # We explicitly upload to the store to ensure association
        client.file_search_stores.upload_to_file_search_store(
            file_search_store_name=session["store_id"],
            file=file_path,
            config={"mime_type": "text/plain"} # Force text/plain for configs
        )
        
        session["file_names"].append(filename)
        
        # Wait briefly for indexing (naive polling)
        time.sleep(2) 
        
        return f"Successfully uploaded {filename} to Knowledge Base."

    except Exception as e:
        return f"Upload failed: {e}"

@mcp.tool
def query_configs(session_id: str, question: str) -> str:
    """
    Ask a question about the uploaded network configurations.
    Uses Gemini 3 Pro Preview with File Search.
    """
    session = _get_session(session_id)
    store_id = session.get("store_id")

    if not store_id:
        return "No configurations uploaded yet. Please upload files first."

    # Define the tool connection
    tool = types.Tool(
        file_search=types.FileSearch(
            file_search_store_names=[store_id]
        )
    )

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=question,
            config=types.GenerateContentConfig(
                tools=[tool],
                system_instruction=NETCONFIG_WHISPERER,
                temperature=0.2
            )
        )
        
        # Check for grounding (citations)
        answer = response.text
        if response.candidates[0].grounding_metadata.grounding_chunks:
            answer += "\n\n(Verified against uploaded config files)"
            
        return answer

    except Exception as e:
        return f"Error processing query: {e}"

@mcp.tool
def get_inventory_summary(session_id: str) -> dict:
    """
    Phase 0: Returns a quick Regex count of features (BGP, ACLs, etc) 
    for all uploaded files. DOES NOT use LLM (Fast & Cheap).
    """
    session = _get_session(session_id)
    summary = {}
    
    # We read from the local temp dir we kept
    for fname in session["file_names"]:
        local_path = os.path.join(session["temp_dir"], fname)
        if os.path.exists(local_path):
            with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
                summary[fname] = _summarize_features_regex(f.read())
                
    return summary

@mcp.tool
def cleanup_session(session_id: str) -> str:
    """Deletes the Google File Search Store and local temp files."""
    session = SESSIONS.get(session_id)
    if not session:
        return "Session not found."

    # Delete Google Store
    if session["store_id"]:
        try:
            client.file_search_stores.delete(name=session["store_id"])
            msg = f"Deleted store {session['store_id']}"
        except Exception as e:
            msg = f"Error deleting store: {e}"
    else:
        msg = "No store to delete"

    # Delete local temp
    if os.path.exists(session["temp_dir"]):
        shutil.rmtree(session["temp_dir"])

    del SESSIONS[session_id]
    return f"Session cleaned up. {msg}"

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transport",
        choices=["http", "stdio"],
        default="http",
        help="MCP transport: http (for VS Code / Gemini-CLI) or stdio (for Claude Desktop)",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if args.transport == "http":
        # HTTP server for VS Code / Gemini-CLI
        mcp.run(transport="http", host=args.host, port=args.port)
    else:
        # Stdio server for Claude Desktop
        mcp.run()
