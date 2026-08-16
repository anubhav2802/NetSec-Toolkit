import ipaddress
import requests


def lookup():

    # --------------------------------------------------
    # Get IP Address
    # --------------------------------------------------

    ip = input("\nEnter IP Address: ")

    # --------------------------------------------------
    # Validate IP Address
    # --------------------------------------------------

    try:

        ip_obj = ipaddress.ip_address(ip)

    except ValueError:

        print("\nInvalid IP Address.")
        return

    # --------------------------------------------------
    # Private IP
    # --------------------------------------------------

    if ip_obj.is_private:

        print("\n" + "=" * 60)
        print("                 IP GEOLOCATION")
        print("=" * 60)

        print(f"IP Address   : {ip}")
        print("Type         : Private IP")
        print("Country      : N/A")
        print("Region       : N/A")
        print("City         : N/A")
        print("Postal Code  : N/A")
        print("Latitude     : N/A")
        print("Longitude    : N/A")
        print("Timezone     : N/A")
        print("ISP          : N/A")
        print("Organization : N/A")
        print("ASN          : N/A")

        print("\nNote:")
        print("Private IP addresses cannot be geolocated")
        print("using public IP geolocation databases.")

        print("=" * 60)

        return

    # --------------------------------------------------
    # Public IP Geolocation
    # --------------------------------------------------

    try:

        url = f"https://ipwho.is/{ip}"

        response = requests.get(
            url,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        # --------------------------------------------------
        # Check API Status
        # --------------------------------------------------

        if not data.get("success"):

            print("\nUnable to retrieve IP information.")

            if data.get("message"):
                print(f"Reason       : {data.get('message')}")

            return

        # --------------------------------------------------
        # Extract Connection Information
        # --------------------------------------------------

        connection = data.get("connection", {})

        # --------------------------------------------------
        # Display Results
        # --------------------------------------------------

        print("\n" + "=" * 60)
        print("                 IP GEOLOCATION")
        print("=" * 60)

        print(f"IP Address   : {data.get('ip')}")
        print(f"Type         : {data.get('type')}")
        print(f"Continent    : {data.get('continent')}")
        print(f"Country      : {data.get('country')}")
        print(f"Country Code : {data.get('country_code')}")
        print(f"Region       : {data.get('region')}")
        print(f"City         : {data.get('city')}")
        print(f"Postal Code  : {data.get('postal')}")
        print(f"Latitude     : {data.get('latitude')}")
        print(f"Longitude    : {data.get('longitude')}")
        print(f"Timezone     : {data.get('timezone', {}).get('id')}")
        print(f"ISP          : {connection.get('isp')}")
        print(f"Organization : {connection.get('org')}")
        print(f"ASN          : {connection.get('asn')}")
        print(f"Domain       : {connection.get('domain')}")

        print("=" * 60)

    # --------------------------------------------------
    # Error Handling
    # --------------------------------------------------

    except requests.exceptions.Timeout:

        print("\nRequest timed out.")

    except requests.exceptions.ConnectionError:

        print("\nCould not connect to the IP geolocation service.")

    except requests.exceptions.RequestException as e:

        print(f"\nNetwork Error: {e}")

    except ValueError:

        print("\nInvalid response received from the API.")