import socket
import requests
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import csv
import os

from bs4 import BeautifulSoup


# -------------------------------------------------------
# Load Wordlist
# -------------------------------------------------------

def load_wordlist():

    try:

        with open(
            "wordlists/subdomains.txt",
            "r"
        ) as file:

            return [

                line.strip()

                for line in file

                if line.strip()

            ]

    except FileNotFoundError:

        print("Wordlist not found.")

        return []


# -------------------------------------------------------
# Generate Random String
# -------------------------------------------------------

def random_subdomain(length=20):

    return "".join(

        random.choice(
            string.ascii_lowercase
        )

        for _ in range(length)

    )


# -------------------------------------------------------
# Wildcard DNS Detection
# -------------------------------------------------------

def wildcard_dns(domain):

    test = random_subdomain()

    hostname = f"{test}.{domain}"

    try:

        socket.gethostbyname(hostname)

        return True

    except:

        return False


# -------------------------------------------------------
# Get Page Title
# -------------------------------------------------------

def get_title(html):

    try:

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        if soup.title:

            return soup.title.text.strip()

        return "N/A"

    except:

        return "N/A"


# -------------------------------------------------------
# Probe HTTP / HTTPS
# -------------------------------------------------------

def probe(url):

    try:

        start = time.time()

        response = requests.get(

            url,

            timeout=5,

            allow_redirects=True

        )

        latency = round(

            (time.time() - start) * 1000,

            2

        )

        server = response.headers.get(

            "Server",

            "Unknown"

        )

        title = get_title(

            response.text

        )

        size = len(

            response.content

        )

        redirect = response.url

        return {

            "status": response.status_code,

            "server": server,

            "title": title,

            "size": size,

            "latency": latency,

            "redirect": redirect

        }

    except:

        return None


# -------------------------------------------------------
# Check One Subdomain
# -------------------------------------------------------

def check_subdomain(domain, subdomain):

    hostname = f"{subdomain}.{domain}"

    try:

        ip = socket.gethostbyname(hostname)

    except:

        return None

    https = probe(

        f"https://{hostname}"

    )

    protocol = "HTTPS"

    if https is None:

        https = probe(

            f"http://{hostname}"

        )

        protocol = "HTTP"

    if https is None:

        return {

            "subdomain": hostname,

            "ip": ip,

            "protocol": "N/A",

            "status": "N/A",

            "server": "Unknown",

            "title": "N/A",

            "redirect": "N/A",

            "latency": "N/A",

            "size": "N/A"

        }

    return {

        "subdomain": hostname,

        "ip": ip,

        "protocol": protocol,

        "status": https["status"],

        "server": https["server"],

        "title": https["title"],

        "redirect": https["redirect"],

        "latency": https["latency"],

        "size": round(

            https["size"] / 1024,

            2

        )

    }

# -------------------------------------------------------
# Worker
# -------------------------------------------------------

def worker(args):

    return check_subdomain(*args)


# -------------------------------------------------------
# Export CSV
# -------------------------------------------------------

def export_csv(results):

    # Create reports folder if it doesn't exist
    os.makedirs(
        "reports",
        exist_ok=True
    )

    try:

        with open(
            "reports/subdomains.csv",
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Subdomain",
                "IP Address",
                "Protocol",
                "HTTP Status",
                "Server",
                "Title",
                "Size(KB)",
                "Latency(ms)",
                "Redirect"
            ])

            for result in results:

                writer.writerow([
                    result["subdomain"],
                    result["ip"],
                    result["protocol"],
                    result["status"],
                    result["server"],
                    result["title"],
                    result["size"],
                    result["latency"],
                    result["redirect"]
                ])

        print("\n✓ Report saved to reports/subdomains.csv")

    except Exception as e:

        print(f"\nCSV Export Error : {e}")


# -------------------------------------------------------
# Statistics
# -------------------------------------------------------

def print_statistics(results, wildcard):

    print("\n" + "=" * 110)

    print("SUMMARY")

    print("=" * 110)

    print(f"Subdomains Found : {len(results)}")

    print(
        f"Wildcard DNS     : {'YES' if wildcard else 'NO'}"
    )

    latencies = [

        result["latency"]

        for result in results

        if isinstance(result["latency"], (int, float))

    ]

    if latencies:

        average = round(

            sum(latencies) / len(latencies),

            2

        )

        fastest = min(latencies)

        slowest = max(latencies)

        print(f"Average Latency : {average} ms")
        print(f"Fastest Response: {fastest} ms")
        print(f"Slowest Response: {slowest} ms")

    else:

        print("Average Latency : N/A")

    print("=" * 110)


# -------------------------------------------------------
# Display Results
# -------------------------------------------------------

def display(results):

    results.sort(
        key=lambda x: x["subdomain"]
    )

    print("\n" + "=" * 170)
    print("SUBDOMAIN ENUMERATION REPORT")
    print("=" * 170)

    print(
        f"{'Subdomain':35}"
        f"{'IP Address':18}"
        f"{'Proto':8}"
        f"{'HTTP':8}"
        f"{'Server':20}"
        f"{'Time(ms)':12}"
        f"{'Size(KB)':10}"
    )

    print("-" * 170)

    for result in results:

        print(

            f"{result['subdomain'][:34]:35}"
            f"{result['ip']:18}"
            f"{result['protocol']:8}"
            f"{str(result['status']):8}"
            f"{result['server'][:19]:20}"
            f"{str(result['latency']):12}"
            f"{str(result['size']):10}"

        )

        print(
            f"   Title    : {result['title'][:90]}"
        )

        print(
            f"   Redirect : {result['redirect']}"
        )

        print("-" * 170)


# -------------------------------------------------------
# Enumerate
# -------------------------------------------------------

def enumerate_subdomains(

    domain,

    wordlist,

    threads=100

):

    tasks = [

        (
            domain,
            word
        )

        for word in wordlist

    ]

    results = []

    with ThreadPoolExecutor(

        max_workers=threads

    ) as executor:

        iterator = executor.map(

            worker,

            tasks

        )

        for result in tqdm(

            iterator,

            total=len(tasks),

            desc="Scanning"

        ):

            if result:

                results.append(result)

    return results

# -------------------------------------------------------
# Main Lookup
# -------------------------------------------------------


def lookup(domain):

    print("\n" + "=" * 70)
    print("             SUBDOMAIN ENUMERATION")
    print("=" * 70)

    # ----------------------------
    # Load Wordlist
    # ----------------------------

    wordlist = load_wordlist()

    if not wordlist:

        return

    print(f"\nLoaded {len(wordlist)} subdomains.")

    # ----------------------------
    # Wildcard DNS
    # ----------------------------

    wildcard = wildcard_dns(domain)

    if wildcard:

        print("\nWARNING : Wildcard DNS detected.")
        print("Results may contain false positives.")

    else:

        print("\nWildcard DNS : Not Detected")

    # ----------------------------
    # Threads
    # ----------------------------

    print("\nChoose Thread Count")

    print("1. 25")
    print("2. 50")
    print("3. 100")
    print("4. 200")

    choice = input("\nChoice : ")

    thread_map = {

        "1":25,
        "2":50,
        "3":100,
        "4":200

    }

    threads = thread_map.get(
        choice,
        100
    )

    print(f"\nUsing {threads} Threads...")

    # ----------------------------
    # Start Scan
    # ----------------------------

    start = time.time()

    results = enumerate_subdomains(

        domain,

        wordlist,

        threads

    )

    end = time.time()

    # ----------------------------
    # Remove Duplicates
    # ----------------------------

    unique = {}

    for result in results:

        unique[
            result["subdomain"]
        ] = result

    results = list(

        unique.values()

    )

    # ----------------------------
    # Display
    # ----------------------------

    display(results)

    # ----------------------------
    # Statistics
    # ----------------------------

    print_statistics(

        results,

        wildcard

    )

    # ----------------------------
    # CSV
    # ----------------------------

    export_csv(results)

    # ----------------------------
    # Final Summary
    # ----------------------------

    print("\nSCAN COMPLETE")

    print("-"*60)

    print(f"Domain Scanned     : {domain}")

    print(f"Words Tested       : {len(wordlist)}")

    print(f"Subdomains Found   : {len(results)}")

    print(f"Threads Used       : {threads}")

    print(f"Total Time         : {round(end-start,2)} seconds")

    if len(wordlist):

        rate = round(

            (len(results)/len(wordlist))*100,

            2

        )

        print(f"Success Rate       : {rate}%")

    print("-"*60)

