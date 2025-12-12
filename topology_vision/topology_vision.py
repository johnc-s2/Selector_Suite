import os
import logging
from PIL import Image
from io import BytesIO
import streamlit as st
from dotenv import load_dotenv
import google.generativeai as genai

# --- 1. Initialization and Configuration ---
# Load environment variables and configure the API key
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Set up logging
logging.basicConfig(level=logging.INFO)

# Configure the Streamlit page
st.set_page_config(
    page_title="Visual Config Generator",
    page_icon="🔍"
)

# Configure the Gemini client once and reuse it
try:
    if GOOGLE_API_KEY:
        genai.configure(api_key=GOOGLE_API_KEY)
        # Updated to use the specified gemini-2.5-pro model
        MODEL = genai.GenerativeModel("gemini-2.5-pro")
    else:
        st.error("🚨 GOOGLE_API_KEY not found. Please set it in your .env file.")
        MODEL = None
except Exception as e:
    st.error(f"Failed to initialize Gemini model: {e}")
    MODEL = None


# --- 2. Core AI Function (Single-Pass) ---
def generate_config_single_pass(image: Image.Image, prompt: str):
    """
    Analyzes the network diagram and prompt in a single pass to generate a final configuration.
    """
    if not MODEL:
        raise ConnectionError("Gemini model is not initialized. Check API key.")

    # This single, detailed prompt combines the best of your previous prompts.
    final_prompt = f"""
    You are an expert network automation engineer. Your task is to generate a production-ready, Cisco-style CLI configuration based on an uploaded network diagram and a textual goal.

    **Primary Goal:**
    Analyze the network topology diagram and the following user request to generate complete and accurate device configurations.
    - **User Request:** "{prompt}"

    ---
    **Configuration Guidelines & Best Practices:**

    **General:**
    - Assume routers operate at Layer 3 and switches at Layer 2.
    - Do not enable routing on switches unless explicitly required.
    - Do not invent IP addresses or VLANs unless they are present in the diagram or prompt.

    **Interfaces:**
    - **Access Ports:** Use `switchport mode access`, assign a `switchport access vlan`, and enable `spanning-tree portfast` and `bpduguard`.
    - **Trunk Ports:** Use `switchport mode trunk`, `switchport trunk encapsulation dot1q`, and specify `switchport trunk allowed vlan`.
    - **Always assume intefaces should be enabled if you add configuration to them unless specified otherwise.

    **Routing Protocols:**
    *** OSPF (Open Shortest Path First) ***:
     - Configure the process using router ospf <process-id>.
     - Define a unique router-id for each device, preferably from a stable loopback interface.
     - Advertise networks using network <IP-address> <wildcard-mask> area <area-id>.
     - Use area 0 for the backbone. Other non-backbone areas must connect to area 0.
     - Prevent routing updates on LAN-facing interfaces with passive-interface <interface-name>.
     - Manually tune paths by setting ip ospf cost <value> on interfaces.
    
    *** BGP (Border Gateway Protocol) ***:
     - Define the local router's ASN with router bgp <local-ASN>.
     - Establish neighborships using neighbor <IP-address> remote-as <remote-ASN>.
     - For iBGP, ensure neighbors have update-source loopback0 and next-hop-self configured where appropriate.
     - For eBGP, neighbors are typically on directly connected links.
     - Activate address families like address-family ipv4 unicast to exchange prefixes.
     - Advertise local networks with the network <prefix> mask <mask> command.
     - Implement policy control using route-map applied to neighbors.

    *** EIGRP (Enhanced Interior Gateway Routing Protocol) ***:
     - Enable the process with router eigrp <ASN>. Named mode (router eigrp <NAME>) is preferred.
     - Under the address family, define the ASN: address-family ipv4 unicast autonomous-system <ASN>.
     - Advertise networks with precise network <IP-address> <wildcard-mask> statements.
     - Use passive-interface on links where you don't want EIGRP neighbors to form.
     - Configure summarization on key interfaces (ip summary-address eigrp <ASN> ...) to optimize routing tables.
     - Use eigrp stub on spoke routers in hub-and-spoke topologies.
     
    *** IS-IS (Intermediate System to Intermediate System) ***:
     - Enable the routing process globally with router isis.
     - Define the router's unique Network Entity Title (NET) address, e.g., net 49.0001.aaaa.bbbb.cccc.00. The area ID is the 49.0001 portion, and the system ID is aaaa.bbbb.cccc. The 00 is the NSEL.
     - Specify the router's role with is-type level-1, level-2-only, or level-1-2.
     - Enable IS-IS on a per-interface basis using ip router isis.

    *** Static Routing ***:
     - Use for simple, predictable paths or as a backup.
     - Define a route with ip route <destination-prefix> <subnet-mask> <next-hop-IP | exit-interface>.
     - Create a floating static route for backup by adding a higher administrative distance (e.g., ip route ... 250). This route only becomes active if the primary, lower-distance route fails.
     - Define a default route to catch all traffic not otherwise specified in the routing table using ip route 0.0.0.0 0.0.0.0 <next-hop-IP | exit-interface>.

    **Security:**
    - Apply basic hardening: `service password-encryption`, `no ip http server`.
    - Use named ACLs (`ip access-list extended NAME`) when security rules are requested.

    ---
    **Output Instructions (Crucial):**

    - **CRITICAL:** Return **only** the clean, ready-to-use CLI configuration blocks.
    - Group the configuration logically for each device using a comment header (e.g., `! Device: R1`).
    - Use consistent indentation.
    - Do **not** include any explanations, commentary, markdown formatting (like ```), or conversational text in your output.
    """

    response = MODEL.generate_content(
        [image, final_prompt],
        generation_config={"temperature": 0.4}
    )
    return response.text.strip()


# --- 3. Streamlit User Interface ---
st.image('logo.jpeg')
st.title("🧠 Visual Configuration Generator")

# Updated markdown to reflect the simplified, single-pass pipeline
st.markdown("""
Welcome to the **Visual Configuration Generator** — a tool designed to analyze your **network diagrams** and generate optimized CLI configurations.

---

### ⚙️ How It Works

1.  **Upload a network diagram** (PNG, JPG, or JPEG).
2.  **Describe your configuration goal**. The more context you provide (device roles, protocols, etc.), the better the output.
3.  Our AI pipeline, powered by **Google's Gemini 2.5 Pro**, will perform a comprehensive analysis to generate a single, optimized configuration.
4.  ✅ View, explain, and **download** your final device configurations.

---

### ✍️ Prompt Tips for Best Results

- Be specific: _“Inter-VLAN routing with ACLs blocking Guest-to-Admin traffic”_
- Mention desired protocols: _“Use OSPF area 0 between routers”_
- Clarify design intent: _“Router 1 is WAN edge, Router 2 is core”_
- Include the operating systems if they are no present in the diagram: _“Cisco IOS, Juniper Junos”_
- Describe any **security requirements**: _“ACLs to restrict access between VLANs”_
- Specify **redundancy**: _“Use HSRP for gateway redundancy”_
- Mention any **specific features**: _“Enable DHCP snooping on VLAN 10”_
- If you have a **table of IP addresses** or VLANs, include it in the prompt.

The more **textual detail** you give, the more accurate and useful your configuration will be.


---
""")

st.markdown("## 🧪 Sample Topology Diagrams")
st.markdown("### 🧰 Try These Network Topology Examples")

# Load and show the samples
col1, col2 = st.columns(2)

with col1:
    st.image("ros.png", caption="Router on a Stick", use_container_width =True)
    with open("ros.png", "rb") as f:
        st.download_button("📥 Download ROS Sample", f, file_name="ros.png")

with col2:
    st.image("napkin.png", caption="Napkin Diagram", use_container_width =True)
    with open("napkin.png", "rb") as f:
        st.download_button("📥 Download Napkin Sample", f, file_name="napkin.png")

st.markdown("### 📤 Upload Your Own Network Diagram")

# --- UI for File Upload and Prompt ---
uploaded_file = st.file_uploader("Upload network diagram (PNG, JPG, JPEG)", type=["png", "jpg", "jpeg"])
prompt = st.text_area("Configuration Goal", placeholder="Example: Configure inter-VLAN routing and OSPF Area 0.")

if st.button("Submit"):
    if uploaded_file and prompt and MODEL:
        try:
            image = Image.open(uploaded_file)

            # Store image in session state for redisplay after rerun
            st.session_state["image_cache"] = image

            st.info("⚙️ Processing your diagram and generating the configuration...")

            # --- Simplified Logic: Single spinner and function call ---
            with st.spinner("🤖 Gemini is analyzing the diagram and building the config..."):
                final_config = generate_config_single_pass(image, prompt)
                st.session_state["final_config"] = final_config

            st.success("✅ Configuration generation complete!")

        except Exception as e:
            st.error(f"An error occurred during generation: {e}")
            logging.error(f"Configuration generation failed: {e}")

    else:
        if not uploaded_file:
            st.warning("⚠️ Please upload a diagram.")
        if not prompt:
            st.warning("⚠️ Please provide a configuration goal.")
        if not MODEL:
             st.error("🚨 Model not available. Please check your API key configuration.")


# --- Post-generation UI (Explain & Download) ---
if "final_config" in st.session_state:
    st.subheader("🧩 Final Configuration")
    if "image_cache" in st.session_state:
        st.image(st.session_state["image_cache"], caption="Uploaded Network Diagram")
    st.code(st.session_state["final_config"], language="bash")

    # Explanation button
    if st.button("🧠 Explain This Configuration"):
        with st.spinner("Explaining the final configuration..."):
            try:
                explanation_prompt = f"""
                You are a helpful Cisco network instructor. Your tone should be educational and clear.
                Please provide a detailed, section-by-section explanation for the following network configuration.
                Use markdown for formatting.
                ---
                Configuration to Explain:
                {st.session_state['final_config']}
                """
                response = MODEL.generate_content(explanation_prompt)
                explanation = response.text.strip()
                st.markdown(explanation)
            except Exception as e:
                st.error(f"An error occurred while generating the explanation: {e}")

    # Download button
    st.download_button(
        label="📥 Download Final Configuration",
        data=st.session_state["final_config"],
        file_name="generated_network_config.txt",
        mime="text/plain",
    )