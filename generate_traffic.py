import requests

for i in range(5):
    try:
        response = requests.get("http://example.com")
        print(f"Request {i+1}: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")
