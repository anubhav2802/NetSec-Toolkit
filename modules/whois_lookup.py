import whois
from datetime import datetime


def format_value(value):
    """Format WHOIS values for clean output."""

    if value is None:
        return "N/A"

    if isinstance(value, list):
        if len(value) == 0:
            return "N/A"

        # If list contains datetimes, use first date
        if isinstance(value[0], datetime):
            return value[0].strftime("%d-%m-%Y")

        return ", ".join(str(v) for v in value)

    if isinstance(value, datetime):
        return value.strftime("%d-%m-%Y")

    return str(value)


def print_field(label, value):
    print(f"{label:<25}: {format_value(value)}")


def lookup(domain):

    try:

        info = whois.whois(domain)

        print("\n" + "=" * 70)
        print("                    WHOIS INFORMATION")
        print("=" * 70)

        # ---------------- Basic Information ---------------- #

        print("\n[BASIC INFORMATION]\n")

        print_field("Domain", info.domain_name)
        print_field("Registrar", info.registrar)
        print_field("Registrar URL", getattr(info, "registrar_url", None))

        print_field("Creation Date", info.creation_date)
        print_field("Updated Date", getattr(info, "updated_date", None))
        print_field("Expiry Date", info.expiration_date)

        print_field("DNSSEC", getattr(info, "dnssec", None))

        # ---------------- Registrant ---------------- #

        print("\n[REGISTRANT INFORMATION]\n")

        print_field("Registrant Name", getattr(info, "name", None))
        print_field("Organization", getattr(info, "org", None))
        print_field("Email", getattr(info, "emails", None))
        print_field("Phone", getattr(info, "phone", None))

        print_field("Street", getattr(info, "address", None))
        print_field("City", getattr(info, "city", None))
        print_field("State", getattr(info, "state", None))
        print_field("Postal Code", getattr(info, "zipcode", None))
        print_field("Country", getattr(info, "country", None))

        # ---------------- Registrar Contact ---------------- #

        print("\n[REGISTRAR CONTACT]\n")

        print_field(
            "Abuse Email",
            getattr(info, "registrar_abuse_contact_email", None)
        )

        print_field(
            "Abuse Phone",
            getattr(info, "registrar_abuse_contact_phone", None)
        )

        # ---------------- Status ---------------- #

        print("\n[DOMAIN STATUS]\n")

        status = getattr(info, "status", None)

        if status:

            if not isinstance(status, list):
                status = [status]

            for s in status:
                print(f"  • {s}")

        else:
            print("  N/A")

        # ---------------- Name Servers ---------------- #

        print("\n[NAME SERVERS]\n")

        servers = getattr(info, "name_servers", None)

        if servers:

            for server in sorted(set(servers)):
                print(f"  • {server}")

        else:
            print("  N/A")

        print("\n" + "=" * 70)

    except Exception as e:

        print("\nError:", e)