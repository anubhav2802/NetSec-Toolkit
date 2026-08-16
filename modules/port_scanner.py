import socket
from concurrent.futures import ThreadPoolExecutor

from modules.common_ports import COMMON_PORTS
from modules.banner_grabber import grab_banner


def scan_port(target, port, service="Unknown"):

    sock = None

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:

            banner = grab_banner(sock)

            return (
                port,
                service,
                "OPEN",
                banner
            )

        else:

            return (
                port,
                service,
                "CLOSED",
                ""
            )

    except Exception:

        return (
            port,
            service,
            "ERROR",
            ""
        )

    finally:

        if sock:
            sock.close()


def scan_worker(args):

    target, port, service = args

    return scan_port(target, port, service)


def display_results(results):

    # Sort according to port number
    results.sort(key=lambda x: x[0])

    print("\n===== SCAN RESULTS =====\n")

    for port, service, status, banner in results:

        if status == "OPEN":

            print(f"[+] Port {port} OPEN ({service})")

            if banner and banner != "No banner":
                print(f"    Banner: {banner}")

        elif status == "CLOSED":

            print(f"[-] Port {port} CLOSED ({service})")

        else:

            print(f"[!] Port {port} ERROR ({service})")


def scan_common_ports(target):

    print("\n[*] Scanning common ports...\n")

    ports = []

    for port, service in COMMON_PORTS.items():

        ports.append(
            (target, port, service)
        )

    with ThreadPoolExecutor(max_workers=20) as executor:

        results = list(
            executor.map(scan_worker, ports)
        )

    display_results(results)


def scan_port_range(target, start_port, end_port):

    print("\n[*] Scanning custom range...\n")

    ports = []

    for port in range(start_port, end_port + 1):

        ports.append(
            (target, port, "Unknown")
        )

    with ThreadPoolExecutor(max_workers=100) as executor:

        results = list(
            executor.map(scan_worker, ports)
        )

    display_results(results)