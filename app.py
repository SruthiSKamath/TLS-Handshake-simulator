import streamlit as st
import random
import hashlib
import datetime
import time
import json

# Page configuration
st.set_page_config(
    page_title="TLS Handshake Simulator-4CB22CS136",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Custom CSS for blue background theme
st.markdown("""
    <div style="background-color:#f0f2f6; padding:10px; border-radius:10px; border:1px solid #ccc;">
        <b>Simulation Overview:</b><br>
        Transport Layer Security (TLS) Handshake Simulator: Simulate the key steps of a TLS handshake. The program should demonstrate the exchange of ClientHello, ServerHello, server certificate, and the key exchange process (e.g., using RSA or Diffie-Hellman) without implementing the full record protocol.
    </div>
""", unsafe_allow_html=True)
st.markdown("""
<style>
    .main {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .handshake-step {
        background-color: rgba(255, 255, 255, 0.1);
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        border-left: 4px solid #4CAF50;
    }
    .success-box {
        background-color: rgba(76, 175, 80, 0.2);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #4CAF50;
    }
    .info-box {
        background-color: rgba(33, 150, 243, 0.2);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #2196F3;
    }
    .header-text {
        text-align: center;
        color: white;
        font-size: 2.5em;
        margin-bottom: 30px;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    .step-header {
        color: #4CAF50;
        font-weight: bold;
        font-size: 1.3em;
    }
    .user-input-section {
        background-color: rgba(255, 255, 255, 0.15);
        padding: 25px;
        border-radius: 15px;
        margin: 20px 0;
        border: 2px solid rgba(255, 255, 255, 0.3);
    }
</style>
""", unsafe_allow_html=True)

class TLSHandshakeSimulator:
    def __init__(self):
        self.supported_ciphers = {
            "TLS 1.3": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384", 
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_CCM_SHA256"
            ],
            "TLS 1.2": [
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            ]
        }

    def generate_server_certificate(self, domain, cert_authority, key_size):
        cert_info = {
            "domain": domain,
            "subject": f"CN={domain}, O=Example Organization, C=US",
            "issuer": f"CN={cert_authority}, O=Certificate Authority, C=US",
            "valid_from": datetime.datetime.now(),
            "valid_until": datetime.datetime.now() + datetime.timedelta(days=365),
            "serial_number": random.randint(1000000000, 9999999999),
            "key_size": key_size,
            "signature_algorithm": "SHA256-RSA",
            "public_key": f"RSA-PUBLIC-KEY-{random.getrandbits(256):064x}"
        }
        return cert_info

    def client_hello(self, tls_version, selected_ciphers, extensions, session_resumption):
        client_random = random.getrandbits(256)
        session_id = random.getrandbits(128) if session_resumption else None
        hello_data = {
            "version": tls_version,
            "random": f"{client_random:064x}"[:16] + "...",
            "session_id": f"{session_id:032x}"[:8] + "..." if session_id else "None",
            "cipher_suites": selected_ciphers,
            "extensions": extensions,
            "session_resumption": session_resumption
        }
        return hello_data, client_random

    def server_hello(self, client_hello_data, client_random, server_preferences):
        server_random = random.getrandbits(256)
        available_ciphers = client_hello_data["cipher_suites"]
        if server_preferences == "security":
            strong = [c for c in available_ciphers if "256" in c or "CHACHA20" in c]
            selected_cipher = random.choice(strong or available_ciphers)
        elif server_preferences == "performance":
            fast = [c for c in available_ciphers if "128" in c]
            selected_cipher = random.choice(fast or available_ciphers)
        else:
            selected_cipher = random.choice(available_ciphers)
        hello_data = {
            "version": client_hello_data["version"],
            "random": f"{server_random:064x}"[:16] + "...",
            "session_id": client_hello_data["session_id"],
            "cipher_suite": selected_cipher,
            "server_preference": server_preferences
        }
        return hello_data, server_random, selected_cipher

    def diffie_hellman_key_exchange(self, dh_parameters):
        prime, generator = dh_parameters
        server_private = random.randint(2, prime - 2)
        server_public = pow(generator, server_private, prime)
        client_private = random.randint(2, prime - 2)
        client_public = pow(generator, client_private, prime)
        shared_secret = pow(client_public, server_private, prime)
        dh_data = {
            "prime": prime,
            "generator": generator,
            "server_public": server_public,
            "client_public": client_public,
            "shared_secret": shared_secret
        }
        return dh_data, shared_secret.to_bytes(32, "big")

    def rsa_key_exchange(self, server_public_key, key_size):
        return random.getrandbits(256).to_bytes(32, "big")

    def derive_keys(self, shared_secret, client_random, server_random, cipher_suite, key_derivation_method):
        key_material = (client_random + server_random).to_bytes(64, "big") + shared_secret
        derived = hashlib.sha256(key_material).digest()
        if key_derivation_method == "HKDF":
            derived = hashlib.sha256(derived + b"tls13 derived").digest()
        keys = {
            "client_write_key": derived[:16].hex(),
            "server_write_key": derived[16:32].hex(),
            "iv_client": derived[32:36].hex(),
            "iv_server": derived[36:40].hex(),
            "cipher_suite": cipher_suite,
            "method": key_derivation_method
        }
        return keys

def simulate_handshake_step(step_name, delay_factor, speed):
    delay = 1.5 / (speed * 0.5) * delay_factor
    with st.spinner(f"🔒 {step_name}..."):
        time.sleep(delay)
    st.success(f"✓ {step_name} completed")

def get_user_inputs():
    st.markdown('<div class="user-input-section">', unsafe_allow_html=True)
    st.markdown("### 🎛️ Connection Configuration")

    col1, col2 = st.columns(2)
    with col1:
        domain = st.text_input("🌐 Target Domain", "example.com")
        tls_version = st.selectbox("🔧 TLS Version", ["TLS 1.3", "TLS 1.2"])
    with col2:
        port = st.number_input("🔌 Port", 1, 65535, 443)
        speed = st.slider("⏱️ Simulation Speed", 1, 10, 5)

    st.markdown("---")
    st.markdown("### 🔐 Security Settings")

    col1, col2 = st.columns(2)
    with col1:
        key_exchange = st.radio("🔄 Key Exchange", ["Diffie-Hellman", "RSA", "ECDHE"])
        dh_parameters = (23, 5) if "Diffie" in key_exchange else None
    with col2:
        cert_authority = st.selectbox("📜 Certificate Authority", ["Let's Encrypt", "DigiCert"])
        key_size = st.selectbox("🔑 Key Size", ["2048-bit", "3072-bit", "4096-bit"])

    st.markdown('</div>', unsafe_allow_html=True)
    return {
        "domain": domain,
        "port": port,
        "tls_version": tls_version,
        "key_exchange": key_exchange,
        "dh_parameters": dh_parameters,
        "cert_authority": cert_authority,
        "key_size": key_size,
        "speed": speed
    }

def main():
    st.markdown('<div class="header-text">🔒 TLS Handshake Simulator-4CB22CS136</div>', unsafe_allow_html=True)
    inputs = get_user_inputs()
    simulator = TLSHandshakeSimulator()

    if st.button("🚀 Start TLS Handshake", use_container_width=True):
        progress = st.progress(0)
        status = st.empty()

        try:
            # Step 1: ClientHello
            status.text("Step 1/6: Sending ClientHello...")
            progress.progress(10)
            client_hello, client_random = simulator.client_hello(inputs["tls_version"], 
                simulator.supported_ciphers[inputs["tls_version"]][:2],
                ["server_name", "supported_groups"], True)
            st.json(client_hello)
            simulate_handshake_step("ClientHello sent", 1.0, inputs["speed"])

            # Step 2: ServerHello
            status.text("Step 2/6: Receiving ServerHello...")
            progress.progress(25)
            server_hello, server_random, cipher = simulator.server_hello(client_hello, client_random, "balanced")
            st.json(server_hello)
            simulate_handshake_step("ServerHello received", 0.8, inputs["speed"])

            # Step 3: Server Certificate
            status.text("Step 3/6: Verifying Server Certificate...")
            progress.progress(45)
            cert = simulator.generate_server_certificate(inputs["domain"], inputs["cert_authority"], inputs["key_size"])
            st.json(cert)
            simulate_handshake_step("Certificate verified", 1.0, inputs["speed"])

            # Step 4: Key Exchange
            status.text("Step 4/6: Performing Key Exchange...")
            progress.progress(65)
            if "Diffie" in inputs["key_exchange"]:
                dh_data, shared = simulator.diffie_hellman_key_exchange(inputs["dh_parameters"])
                st.json(dh_data)
            else:
                shared = simulator.rsa_key_exchange("public_key", inputs["key_size"])
                st.info("RSA key exchange completed.")
            simulate_handshake_step("Key Exchange complete", 1.0, inputs["speed"])

            # Step 5: Key Derivation
            status.text("Step 5/6: Deriving Keys...")
            progress.progress(85)
            keys = simulator.derive_keys(shared, client_random, server_random, cipher, "HKDF")
            st.json(keys)
            simulate_handshake_step("Key Derivation complete", 1.0, inputs["speed"])

            # Step 6: Completion
            status.text("Step 6/6: Handshake Complete!")
            progress.progress(100)
            st.success("✅ TLS Handshake Completed Successfully!")
           
        except Exception as e:
            st.error(f"❌ Handshake failed: {str(e)}")
            status.text("Handshake failed!")

if __name__ == "__main__":
    main()
