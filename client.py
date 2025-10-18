import socket, threading, pickle, json, os, base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000


# ---------- Helper Functions ----------
def save_message(username, entry):
    """Save message to JSON log"""
    fname = f"messages_{username}.json"
    with open(fname, "a") as f:
        f.write(json.dumps(entry) + "\n")


def rsa_generate(username):
    """Generate RSA key pair"""
    key = RSA.generate(2048)
    with open(f"{username}_private.pem", "wb") as f:
        f.write(key.export_key())
    with open(f"{username}_public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    return key


def rsa_load_or_create(username):
    """Load or create key pair"""
    if not os.path.exists(f"{username}_private.pem"):
        return rsa_generate(username)
    else:
        return RSA.import_key(open(f"{username}_private.pem", "rb").read())


# ---------- Client Class ----------
class Client:
    def __init__(self, username, peer):
        self.username = username
        self.peer = peer
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        self.keypair = rsa_load_or_create(username)
        self.pubkey = self.keypair.publickey().export_key()

        # Register with server
        self.sock.send(pickle.dumps((self.username, self.pubkey)))
        print(f"[{self.username}] Connected to server and registered.")
        print(f"Chatting securely with {self.peer}. Type 'exit' anytime.\n")

        self.session_keys = {}  # peer → AES key

    # ---------------- Receiver Thread ----------------
    def listen(self):
        """Receive messages or session keys"""
        while True:
            try:
                data = self.sock.recv(8192)
                if not data:
                    break
                sender, enc_payload = pickle.loads(data)
                self.handle_incoming(sender, enc_payload)
            except Exception as e:
                print(f"[{self.username}] Receive error: {e}")
                break

    # ---------------- Handle Incoming Messages ----------------
    def handle_incoming(self, sender, enc_payload):
        """Decrypt incoming message or session key"""
        if enc_payload.startswith(b"SESSIONKEY:"):
            enc_key = enc_payload.split(b":", 1)[1]
            cipher_rsa = PKCS1_OAEP.new(self.keypair)
            aes_key = cipher_rsa.decrypt(base64.b64decode(enc_key))
            self.session_keys[sender] = aes_key
            print(f"[{self.username}] 🔐 Session key established with {sender}.\n")
        else:
            try:
                raw = base64.b64decode(enc_payload)
                nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
                cipher_aes = AES.new(self.session_keys[sender], AES.MODE_EAX, nonce)
                plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()

                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"\n[{timestamp}] {sender}: {plaintext}\n")

                # Log received message
                save_message(self.username, {
                    "direction": "received",
                    "from": sender,
                    "plaintext": plaintext,
                    "ciphertext": enc_payload.decode(),
                    "timestamp": timestamp
                })
            except Exception as e:
                print(f"[{self.username}] ❌ Decryption failed from {sender}: {e}")

    # ---------------- Send Session Key ----------------
    def send_session_key(self):
        """Send AES key encrypted with peer's public key"""
        pub_path = f"{self.peer}_public.pem"
        if not os.path.exists(pub_path):
            print(f"[{self.username}] Missing {pub_path}. Share public key file first.")
            return
        peer_pub = RSA.import_key(open(pub_path, "rb").read())
        aes_key = get_random_bytes(32)
        cipher_rsa = PKCS1_OAEP.new(peer_pub)
        enc_key = cipher_rsa.encrypt(aes_key)
        self.session_keys[self.peer] = aes_key
        payload = b"SESSIONKEY:" + base64.b64encode(enc_key)
        self.sock.send(pickle.dumps((self.username, self.peer, payload)))

    # ---------------- Encrypt + Send Message ----------------
    def send_message(self, plaintext):
        """Encrypt and send message"""
        if self.peer not in self.session_keys:
            self.send_session_key()

        aes_key = self.session_keys[self.peer]
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode())
        enc_payload = base64.b64encode(cipher_aes.nonce + tag + ciphertext)
        self.sock.send(pickle.dumps((self.username, self.peer, enc_payload)))

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] Me: {plaintext}")

        # Log sent message
        save_message(self.username, {
            "direction": "sent",
            "to": self.peer,
            "plaintext": plaintext,
            "ciphertext": enc_payload.decode(),
            "timestamp": timestamp
        })


# ---------- MAIN ----------
def main():
    print("===== COSC3796 Secure Chat Application =====")
    username = input("Enter your username (Alice/Bob): ").strip()
    peer = input("Enter the username you want to chat with: ").strip()

    client = Client(username, peer)

    # Start listening thread
    threading.Thread(target=client.listen, daemon=True).start()

    # Chat loop
    while True:
        msg = input()
        if msg.lower() == "exit":
            print(f"[{username}] Chat ended.")
            break
        if msg.strip():
            client.send_message(msg)


if __name__ == "__main__":
    main()
