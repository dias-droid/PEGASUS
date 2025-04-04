import requests
import termcolor
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

class JSAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.js_files = []
        self.endpoints = []
        self.sensitive_data = []

    def extract_js_files(self, soup):
        """Extract JavaScript files from the page"""
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            js_url = urljoin(self.target_url, script['src'])
            self.js_files.append(js_url)

    def find_endpoints(self, content):
        """Find API endpoints in JavaScript code"""
        # Common endpoint patterns
        patterns = [
            r'["\']/api/[^"\']*["\']',
            r'["\']/v[0-9]+/[^"\']*["\']',
            r'["\']/rest/[^"\']*["\']',
            r'["\']/graphql["\']',
            r'fetch\(["\']([^"\']+)["\']\)',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']\)',
            r'\.ajax\({\s*url:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group(1) if len(match.groups()) > 0 else match.group(0)
                endpoint = endpoint.strip("'\"")
                if endpoint not in self.endpoints:
                    self.endpoints.append(endpoint)

    def find_sensitive_data(self, content):
        """Find potentially sensitive data in JavaScript code"""
        patterns = {
            'API Keys': r'["\'](api[_-]?key|apikey)["\']\s*[:=]\s*["\']([^"\']+)["\']',
            'Tokens': r'["\'](token|access_token|refresh_token)["\']\s*[:=]\s*["\']([^"\']+)["\']',
            'Passwords': r'["\'](password|passwd|pwd)["\']\s*[:=]\s*["\']([^"\']+)["\']',
            'Secrets': r'["\'](secret|private_key)["\']\s*[:=]\s*["\']([^"\']+)["\']'
        }
        
        for data_type, pattern in patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self.sensitive_data.append({
                    'type': data_type,
                    'key': match.group(1),
                    'value': match.group(2)
                })

    def analyze(self):
        """Start JavaScript analysis"""
        print(termcolor.colored("\n[*] Starting JavaScript analysis...", "cyan"))
        
        try:
            # Get main page
            response = requests.get(self.target_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract and analyze JavaScript files
            self.extract_js_files(soup)
            
            for js_file in self.js_files:
                try:
                    js_response = requests.get(js_file, verify=False)
                    content = js_response.text
                    
                    # Analyze JavaScript content
                    self.find_endpoints(content)
                    self.find_sensitive_data(content)
                    
                except Exception as e:
                    print(termcolor.colored(f"[-] Error analyzing {js_file}: {str(e)}", "red"))
            
            # Print findings
            if self.endpoints:
                print(termcolor.colored("\n[+] Found endpoints:", "green"))
                for endpoint in self.endpoints:
                    print(termcolor.colored(f"  - {endpoint}", "cyan"))
            
            if self.sensitive_data:
                print(termcolor.colored("\n[!] Found sensitive data:", "red"))
                for data in self.sensitive_data:
                    print(termcolor.colored(f"  - {data['type']}: {data['key']}", "yellow"))
            
            return {
                'js_files': self.js_files,
                'endpoints': self.endpoints,
                'sensitive_data': self.sensitive_data
            }
            
        except Exception as e:
            print(termcolor.colored(f"\n[-] Error during analysis: {str(e)}", "red"))
            return None 