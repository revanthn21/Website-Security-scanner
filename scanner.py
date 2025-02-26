import requests
from bs4 import BeautifulSoup

class WebAppScanner:
    def __init__(self, url):
        self.url = url

    def send_request(self, url, params=None):
        try:
            if params:
                response = requests.get(url, params=params)
            else:
                response = requests.get(url)
            return response
        except requests.RequestException as e:
            return None

    def find_forms(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        return soup.find_all('form')

    def detect_sql_injection(self, url):
        payloads = ["' OR 1=1 --", "' OR 'a'='a"]
        for payload in payloads:
            params = {"input": payload}
            response = self.send_request(url, params=params)
            if response and "error" in response.text.lower():
                return f"SQL Injection vulnerability found at {url} with payload {payload}"
        return "No SQL Injection vulnerability found."

    def detect_xss(self, url):
        payload = "<script>alert('XSS')</script>"
        response = self.send_request(url, params={"input": payload})
        if response and payload in response.text:
            return f"XSS vulnerability found at {url}"
        return "No XSS vulnerability found."

    def detect_csrf(self, forms):
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                return f"CSRF vulnerability found in form: {form}"
        return "No CSRF vulnerability found."
