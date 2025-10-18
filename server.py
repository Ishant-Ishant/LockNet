import socket
import threading
import pickle

HOST = '127.0.0.1'
PORT = 5000

clients = {}        # username → connection
public_keys = {}    # username → RSA public key


def handle_client(conn):
    try:
        # Receive registration info (username, public_key)
        reg = conn.recv(4096)
        username, pub_key = pickle.loads(reg)
        clients[username] = conn
        public_keys[username] = pub_key
        print(f"[SERVER] {username} connected. Public key registered.\n")

        while True:
            data = conn.recv(8192)
            if not data:
                break

            sender, target, ciphertext = pickle.loads(data)

            # Display encrypted message (first 100 chars for clarity)
            display_cipher = (
                ciphertext[:100] + b"..."
                if isinstance(ciphertext, bytes) and len(ciphertext) > 100
                else ciphertext
            )
            print(f"[SERVER] Encrypted message from {sender} → {target}: {display_cipher}\n")

            # Forward message to target if connected
            if target in clients:
                clients[target].send(pickle.dumps((sender, ciphertext)))
            else:
                print(f"[SERVER] {target} not connected. Message dropped.\n")

    except Exception as e:
        print(f"[SERVER] Error: {e}")
    finally:
        conn.close()
        for name, c in list(clients.items()):
            if c == conn:
                del clients[name]
                print(f"[SERVER] {name} disconnected.")
                break


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SERVER] Running on {HOST}:{PORT}\n")
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
