#!/usr/bin/env python3
import argparse
import sys
from termcolor import colored
import os

# Protection System
TOOL_NAME = "PEGASUS"
AUTHOR = "letda kes dr. Sobri, S.Kom"
EMAIL = "muhammadsobrimaulana31@gmail.com"

def validate_identity():
    if TOOL_NAME != "PEGASUS" or AUTHOR != "letda kes dr. Sobri, S.Kom" or EMAIL != "muhammadsobrimaulana31@gmail.com":
        print(colored("[!] Unauthorized modification detected. Pegasus is shutting down.", "red"))
        sys.exit(1)

def activate():
    print(colored("\n🔐 PEGASUS Activation System", "cyan"))
    print(colored("===========================", "cyan"))
    code = input(colored("Enter activation code: ", "yellow"))
    if code.strip().lower() != "sobri":
        print(colored("[!] Activation failed. Exiting.", "red"))
        sys.exit(1)
    print(colored("[✓] Activation successful!", "green"))

def print_banner():
    banner = """
    ██████╗ ███████╗ ██████╗  █████╗ ███████╗██╗   ██╗███████╗
    ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔════╝██║   ██║██╔════╝
    ██████╔╝█████╗  ██║  ███╗███████║███████╗██║   ██║███████╗
    ██╔═══╝ ██╔══╝  ██║   ██║██╔══██║╚════██║╚██╗ ██╔╝╚════██║
    ██║     ███████╗╚██████╔╝██║  ██║███████║ ╚████╔╝ ███████║
    ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝
    """
    print(colored(banner, "cyan"))
    print(colored("Unified Web Vulnerability Toolkit", "cyan"))
    print(colored("Author: " + AUTHOR, "cyan"))
    print(colored("Contact: " + EMAIL, "cyan"))
    print(colored("=" * 60, "cyan"))

def main():
    # Validate tool integrity
    validate_identity()
    
    # Print banner
    print_banner()
    
    # Activation check
    activate()
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="PEGASUS - Web Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--sqli", action="store_true", help="Enable SQL Injection scanning")
    parser.add_argument("--xss", action="store_true", help="Enable XSS scanning")
    parser.add_argument("--csrf", action="store_true", help="Enable CSRF scanning")
    parser.add_argument("--dir", action="store_true", help="Enable directory bruteforcing")
    parser.add_argument("--session", action="store_true", help="Enable session analysis")
    parser.add_argument("--js", action="store_true", help="Enable JavaScript analysis")
    parser.add_argument("--bypass", action="store_true", help="Enable 403 bypass testing")
    
    args = parser.parse_args()
    
    # Import modules based on selected options
    if args.sqli:
        from core.sqli_scanner import SQLIScanner
        scanner = SQLIScanner(args.target)
        scanner.scan()
    
    if args.xss:
        from core.xss_scanner import XSSScanner
        scanner = XSSScanner(args.target)
        scanner.scan()
    
    if args.csrf:
        from core.csrf_tester import CSRFTester
        tester = CSRFTester(args.target)
        tester.test()
    
    if args.dir:
        from core.dir_brute import DirBrute
        bruteforcer = DirBrute(args.target)
        bruteforcer.scan()
    
    if args.session:
        from core.session_fixation import SessionFixation
        from core.session_file import SessionFile
        session_fix = SessionFixation(args.target)
        session_file = SessionFile(args.target)
        session_fix.test()
        session_file.scan()
    
    if args.js:
        from core.js_secret_scanner import JSSecretScanner
        scanner = JSSecretScanner(args.target)
        scanner.scan()
    
    if args.bypass:
        from core.bypasser import Bypasser
        bypasser = Bypasser(args.target)
        bypasser.test()

if __name__ == "__main__":
    main() 