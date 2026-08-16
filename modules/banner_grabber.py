import socket


def grab_banner(sock):

    try:
        sock.settimeout(2)

        banner = sock.recv(1024)

        if banner:
            return banner.decode(errors="ignore").strip()

        return "No banner"

    except socket.timeout:
        return "No banner"

    except Exception:
        return "No banner"