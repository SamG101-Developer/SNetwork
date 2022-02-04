import socket


if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((socket.gethostbyname(socket.gethostname()), 12345))

    while True:
        send = input("[SEND]").encode()
        s.send(send)

        if send.lower() == "quit": break

    s.close()
