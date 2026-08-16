from modules import port_scanner
from modules import whois_lookup
from modules import dns_lookup
from modules import ssl_checker
from modules import http_headers
from modules import subdomain_scanner
from modules import hash_identifier
from modules import password_strength
from modules import ip_geolocation
def main():

    while True:

        print("\n" + "=" * 60)
        print("                 CYBER SECURITY TOOLKIT")
        print("=" * 60)

        print("1. Port Scanner")
        print("2. WHOIS Lookup")
        print("3. DNS Lookup")
        print("4. SSL/TLS Certificate Analyzer")
        print("5. HTTP Security Header Scanner")
        print("6. Subdomain Enumerator")
        print("7. Hash Identifier")
        print("8. Password Strength Checker")
        print("9. IP Geolocation")
        print("0. Exit")

        print("=" * 60)

        choice = input("Enter your choice: ")

        # --------------------------------------------------
        # Port Scanner
        # --------------------------------------------------

        if choice == "1":

            host = input("\nEnter IP Address or Domain: ")

            print("\n1. Scan Common Ports")
            print("2. Scan Custom Port Range")

            scan_choice = input("Enter choice: ")

            if scan_choice == "1":

                port_scanner.scan_common_ports(host)

            elif scan_choice == "2":

                try:

                    start_port = int(input("Start Port : "))
                    end_port = int(input("End Port   : "))

                    if (
                        start_port < 1
                        or end_port > 65535
                        or start_port > end_port
                    ):

                        print("\nInvalid Port Range.")

                    else:

                        port_scanner.scan_port_range(
                            host,
                            start_port,
                            end_port
                        )

                except ValueError:

                    print("\nPlease enter valid port numbers.")

            else:

                print("\nInvalid choice.")

        # --------------------------------------------------
        # WHOIS Lookup
        # --------------------------------------------------

        elif choice == "2":

            domain = input("\nEnter Domain: ")

            whois_lookup.lookup(domain)

        # --------------------------------------------------
        # DNS Lookup
        # --------------------------------------------------

        elif choice == "3":

            domain = input("\nEnter Domain: ")

            dns_lookup.lookup(domain)

        # --------------------------------------------------
        # SSL/TLS Certificate Analyzer
        # --------------------------------------------------

        elif choice == "4":

            domain = input("\nEnter Domain: ")

            ssl_checker.lookup(domain)

        # --------------------------------------------------
        # HTTP Security Header Scanner
        # --------------------------------------------------

        elif choice == "5":

            domain = input("\nEnter Domain: ")

            http_headers.lookup(domain)

        # --------------------------------------------------
        # Subdomain Enumerator
        # --------------------------------------------------

        elif choice == "6":

            domain = input("\nEnter Domain: ")

            subdomain_scanner.lookup(domain)

        # --------------------------------------------------
        # IP Geolocation
        # --------------------------------------------------

        elif choice == "9":

            ip_geolocation.lookup()

        # --------------------------------------------------
        # Hash Identifier
        # --------------------------------------------------


        elif choice == "7":

            hash_identifier.lookup()


        # --------------------------------------------------
        # Password Strength Checker
        # --------------------------------------------------

        
        elif choice == "8":

            password_strength.lookup()

        # --------------------------------------------------
        # Exit
        # --------------------------------------------------

        elif choice == "0":

            print("\nThank you for using Cyber Security Toolkit.")
            print("Goodbye!")

            break

        # --------------------------------------------------
        # Invalid Choice
        # --------------------------------------------------

        else:

            print("\nInvalid choice. Please try again.")


if __name__ == "__main__":

    main()