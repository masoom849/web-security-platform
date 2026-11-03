from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
def check_website(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print ("invalid URL,enter a complete HTTP OR HTTPS URL.")
        return
    req = Request(
        url,
        headers={"User-Agent":
    "websecurityplatform/1.0"},
        method="GET"
    )
    try:
        with urlopen(req, timeout=10) as response:
           headers = response.headers
        print ("\n--- website security check ---")
        print ("website:", url)
        print ("HTTPS enabled:", parsed.scheme == "https")
        print ("HTTP status:", response.status)
       
        checks = [
              "content-security-policy",
              "strict-transport-security",
              "x-content-type-options",
              "x-frame-options",  
        ]
        print("\nsecurity headers:")
        for header in checks: 
            if header in headers:
                print (f"[PRESENT] {header}")
            else:
                print (f"[MISSING] {header}")
    except HTTPerror as error:
          print ("HTTP error:", error.code)
    except URLerror as error:
          print ("connection error:", error.reason)
    except Timeouterror:
          print ("request timed out,")
if __name__ == "__main__":
    target = input("enter an authorized test website URL:").strip()
    check_website(target)                

