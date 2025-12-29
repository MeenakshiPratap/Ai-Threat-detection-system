# geo_lookup.py
import requests

def get_country_by_ip(ip_address):
    try:
        response = requests.get(f"https://ipapi.co/{ip_address}/country_name/", timeout=2)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown"
    except Exception:
        return "Unknown"
