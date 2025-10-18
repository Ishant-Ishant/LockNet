# 🔒 LockNet – End-to-End Encrypted Chat System

**Course:** COSC-3796 – Network Security  
**Assignment:** 1  
**Student:** Ishant Ishant   
**Instructor:** Prof. Syed Muhammad Danish  
**Teaching Assistant:** Annas Furqan Pasha  
**Submission Date:** 18 October 2025  

---

## 🧠 Project Overview
LockNet is a secure chat application developed in Python that demonstrates **End-to-End Encryption (E2EE)** using a hybrid of **RSA** and **AES** algorithms.  
It allows two users to exchange private messages while ensuring full confidentiality and data integrity.

---

## 🧩 System Components
- **server.py** → Acts as a secure relay. It only transfers encrypted messages between users, never storing or reading plaintext.  
- **client.py** → Handles encryption, decryption, key exchange, and local message logging.  
- **JSON files** → Store chat logs (messages with timestamps for replay protection).  
- **PEM files** → Store each user's public and private RSA keys.

Each client automatically generates its own RSA key pair, and a shared AES session key is established for message exchange.

---

## ⚙️ Features
- RSA-based key generation and exchange  
- AES encryption for message content  
- Server only sees encrypted ciphertext  
- JSON chat logs include timestamps to detect replay attacks  
- Each message encrypted and decrypted in real time


---

## ▶️ How to Run

---

1️⃣ Start the Server
Open one terminal and run:
python server.py

--------------------------------

2️⃣ Start the Clients
Open two more terminals and run:
python client.py

--------------------------------

When prompted:

1️⃣ User 1 → enter username Alice, chatting with Bob

2️⃣ User 2 → enter username Bob, chatting with Alice

--------------------------------

🔒 Then exchange messages securely.
