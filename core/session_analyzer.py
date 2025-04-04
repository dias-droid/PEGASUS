import requests
import termcolor
import json
from urllib.parse import urljoin

class SessionAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session_data = {}
        self.vulnerabilities = []

    def analyze_cookies(self, response):
        """Analyze cookies for security issues"""
        cookies = response.cookies
        
        for cookie in cookies:
            cookie_data = {
                'name': cookie.name,
                'value': cookie.value,
                'secure': cookie.secure,
                'httpOnly': cookie.has_nonstandard_attr('HttpOnly'),
                'domain': cookie.domain,
                'path': cookie.path
            }
            
            # Check for security issues
            if not cookie.secure:
                self.vulnerabilities.append({
                    'type': 'Insecure Cookie',
                    'details': f'Cookie {cookie.name} is not secure'
                })
            
            if not cookie.has_nonstandard_attr('HttpOnly'):
                self.vulnerabilities.append({
                    'type': 'Missing HttpOnly',
                    'details': f'Cookie {cookie.name} is missing HttpOnly flag'
                })
            
            self.session_data['cookies'] = cookie_data

    def analyze_headers(self, response):
        """Analyze response headers for security issues"""
        headers = dict(response.headers)
        
        # Check for security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Content-Security-Policy': 'Missing CSP header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header'
        }
        
        for header, message in security_headers.items():
            if header not in headers:
                self.vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'details': message
                })
        
        self.session_data['headers'] = headers

    def analyze(self):
        """Start session analysis"""
        print(termcolor.colored("\n[*] Starting session analysis...", "cyan"))
        
        try:
            response = requests.get(self.target_url, verify=False)
            
            # Analyze cookies and headers
            self.analyze_cookies(response)
            self.analyze_headers(response)
            
            # Print findings
            if self.vulnerabilities:
                print(termcolor.colored("\n[!] Found vulnerabilities:", "red"))
                for vuln in self.vulnerabilities:
                    print(termcolor.colored(f"  - {vuln['type']}: {vuln['details']}", "yellow"))
            else:
                print(termcolor.colored("\n[+] No major vulnerabilities found", "green"))
            
            return {
                'vulnerabilities': self.vulnerabilities,
                'session_data': self.session_data
            }
            
        except Exception as e:
            print(termcolor.colored(f"\n[-] Error during analysis: {str(e)}", "red"))
            return None 