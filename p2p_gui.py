import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
from crypto_utils import *
import tkinter.simpledialog as simpledialog

class SecureChatApp:
    def __init__(self, master, is_server=False):
        self.master = master
        self.master.title("Secure P2P Messenger")
        self.is_server = is_server
        self.conn = None
        self.alive = True
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, height=20, width=50)
        self.text_area.pack()
        self.text_area.config(state=tk.DISABLED)

        self.entry = tk.Entry(master, width=40)
        self.entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.send_btn = tk.Button(master, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT, padx=5, pady=5)

        self.password = simpledialog.askstring("Password", "Enter shared password:", show="*")
        if not self.password:
            self.master.destroy()
            return
        self.salt = b'secure_salt_1234'
        self.key = derive_key(self.password, self.salt)

        threading.Thread(target=self.network_thread).start()

    def on_close(self):
        self.alive = False
        if self.conn:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
            except:
                pass
        self.master.destroy()

    def append_text(self, msg):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.config(state=tk.DISABLED)
        self.text_area.see(tk.END)

    def network_thread(self):
        if self.is_server:
            server_socket = socket.socket()
            server_socket.bind(("0.0.0.0", 5000))
            server_socket.listen(1)
            self.append_text("Waiting for connection...")
            self.conn, _ = server_socket.accept()
            self.append_text("Connected.")
        else:
            self.conn = socket.socket()
            self.conn.connect(("localhost", 5000))
            self.append_text("Connected to server.")

        self.conn.settimeout(1.0)
        while self.alive:
            try:
                data = self.conn.recv(4096).decode()
                if data:
                    decrypted = decrypt_message(data, self.key)
                    self.append_text(f"[Friend] {decrypted} (Encrypted: {data})")
            except socket.timeout:
                continue
            except:
                break

    def send_message(self):
        msg = self.entry.get()
        if msg and self.conn:
            enc = encrypt_message(msg, self.key)
            self.conn.send(enc.encode())
            self.append_text(f"[You] {msg} (Encrypted: {enc})")
            self.entry.delete(0, tk.END)

if __name__ == "__main__":
    import sys
    root = tk.Tk()
    app = SecureChatApp(root, is_server=("server" in sys.argv))
    root.mainloop()
