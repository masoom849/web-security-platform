import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def scan_website(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        print("Invalid website URL.")
        return

    print("\n=== ADVANCED WEB SECURITY SCANNER ===")
    print("Target:", url)
    print("Scan time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "WebSecurityPlatform/2.0"}
        )

        print("\nHTTP STATUS:", response.status_code)
        print("FINAL URL:", response.url)
        print("HTTPS:", response.url.startswith("https://"))

        print("\n=== SECURITY HEADERS ===")

        present = 0

        for header in SECURITY_HEADERS:
            if header.lower() in {
                h.lower() for h in response.headers
            }:
                print(f"[PRESENT] {header}")
                present += 1
            else:
                print(f"[MISSING] {header}")

        score = round(present / len(SECURITY_HEADERS) * 100)

        print("\n=== BASIC HEADER SCORE ===")
        print(f"{score}/100 ({present}/{len(SECURITY_HEADERS)} headers)")

        print("\nNote: This score checks headers only.")
        print("It is not a complete website security assessment.")

    except requests.exceptions.SSLError:
        print("SSL/TLS certificate verification failed.")

    except requests.exceptions.Timeout:
        print("Request timed out.")

    except requests.exceptions.ConnectionError:
        print("Could not connect to the website.")

    except requests.exceptions.RequestException as error:
        print("Request error:", error)


if __name__ == "__main__":
    target = input("Enter an authorized test website URL: ").strip()
    scan_website(target)
