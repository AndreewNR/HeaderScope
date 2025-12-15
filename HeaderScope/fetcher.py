import requests
import socket
from urllib.parse import urlparse


def fetch_headers(url: str):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip_address = "No resuelta"

    response = requests.get(
        url,
        timeout=10,
        allow_redirects=True,
        headers={"User-Agent": "HeaderScope/1.0"}
    )

    headers = dict(response.headers)
    server = headers.get("Server", "No divulgado")

    target_info = {
        "url": url,
        "domain": hostname,
        "ip": ip_address,
        "server": server,
        "headers": headers
    }

    return headers, target_info
