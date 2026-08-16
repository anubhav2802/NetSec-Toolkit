import socket
import ssl
from datetime import datetime


# ---------------------------------------------------------
# Get Certificate
# ---------------------------------------------------------

def get_certificate(domain, port=443):

    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, port), timeout=5) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssock:

                cert = ssock.getpeercert()

                tls_version = ssock.version()

                cipher = ssock.cipher()

                return cert, tls_version, cipher

    except Exception as e:

        print(f"\nError: {e}")

        return None, None, None


# ---------------------------------------------------------
# Subject
# ---------------------------------------------------------

def print_subject(cert):

    print("\n" + "-" * 60)
    print("CERTIFICATE SUBJECT")
    print("-" * 60)

    subject = dict(x[0] for x in cert["subject"])

    print(f"Common Name        : {subject.get('commonName', 'N/A')}")
    print(f"Organization       : {subject.get('organizationName', 'N/A')}")
    print(f"Country            : {subject.get('countryName', 'N/A')}")


# ---------------------------------------------------------
# Issuer
# ---------------------------------------------------------

def print_issuer(cert):

    print("\n" + "-" * 60)
    print("CERTIFICATE ISSUER")
    print("-" * 60)

    issuer = dict(x[0] for x in cert["issuer"])

    print(f"Common Name        : {issuer.get('commonName', 'N/A')}")
    print(f"Organization       : {issuer.get('organizationName', 'N/A')}")
    print(f"Country            : {issuer.get('countryName', 'N/A')}")


# ---------------------------------------------------------
# Validity
# ---------------------------------------------------------

def print_validity(cert):

    print("\n" + "-" * 60)
    print("VALIDITY")
    print("-" * 60)

    issued = datetime.strptime(
        cert["notBefore"],
        "%b %d %H:%M:%S %Y %Z"
    )

    expiry = datetime.strptime(
        cert["notAfter"],
        "%b %d %H:%M:%S %Y %Z"
    )

    remaining = (expiry - datetime.utcnow()).days

    print(
        f"Issued On          : "
        f"{issued.strftime('%d %b %Y')}"
    )

    print(
        f"Expires On         : "
        f"{expiry.strftime('%d %b %Y')}"
    )

    print(
        f"Days Remaining     : "
        f"{remaining}"
    )


# ---------------------------------------------------------
# TLS Information
# ---------------------------------------------------------

def print_tls_info(tls_version, cipher):

    print("\n" + "-" * 60)
    print("TLS INFORMATION")
    print("-" * 60)

    print(f"TLS Version        : {tls_version}")
    print(f"Cipher Suite       : {cipher[0]}")
    print(f"Protocol Bits      : {cipher[2]}")


# ---------------------------------------------------------
# SAN
# ---------------------------------------------------------

def print_san(cert):

    print("\n" + "-" * 60)
    print("SUBJECT ALTERNATIVE NAMES")
    print("-" * 60)

    san = cert.get("subjectAltName", [])

    if not san:
        print("No SAN entries found.")
        return

    for _, name in san:
        print(f"• {name}")


# ---------------------------------------------------------
# Status
# ---------------------------------------------------------

def print_status(cert):

    print("\n" + "-" * 60)
    print("STATUS")
    print("-" * 60)

    expiry = datetime.strptime(
        cert["notAfter"],
        "%b %d %H:%M:%S %Y %Z"
    )

    remaining = (expiry - datetime.utcnow()).days

    print("Certificate Valid  : YES")

    if remaining <= 30:

        print("WARNING            : Certificate expires soon!")

    else:

        print("Certificate Health : GOOD")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def lookup(domain):

    cert, tls_version, cipher = get_certificate(domain)

    if cert is None:
        return

    print("\n" + "=" * 60)
    print("           SSL / TLS CERTIFICATE REPORT")
    print("=" * 60)

    print(f"\nTarget Domain      : {domain}")
    print("Port               : 443")

    print_subject(cert)

    print_issuer(cert)

    print_validity(cert)

    print_tls_info(
        tls_version,
        cipher
    )

    print_san(cert)

    print_status(cert)

    print("\n" + "=" * 60)