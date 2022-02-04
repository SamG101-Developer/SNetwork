import socket


if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostbyname(socket.gethostname()), 12345))
    s.listen(1)
    c, addr = s.accept()

    print("[CONN] %s:%d" % (addr[0], addr[1]))

    while True:
        recv = c.recv(1024).decode()
        if recv.lower() == "quit": break

        print("[RECV] %s" % recv)
    s.close()
