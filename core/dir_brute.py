import requests
import termcolor
import concurrent.futures
from urllib.parse import urljoin
import os

class DirBrute:
    def __init__(self, target_url):
        self.target_url = target_url
        self.found_dirs = []
        self.common_paths = [
            '/admin', '/login', '/wp-admin', '/uploads', '/api',
            '/backup', '/config', '/db', '/database', '/dev',
            '/test', '/beta', '/staging', '/prod', '/production',
            '/old', '/new', '/temp', '/tmp', '/bak', '/backup',
            '/admin.php', '/administrator', '/moderator', '/webmaster',
            '/user', '/users', '/member', '/members', '/account',
            '/accounts', '/profile', '/profiles', '/dashboard',
            '/cp', '/cpanel', '/panel', '/admin-panel', '/adminpanel',
            '/adm', '/mod', '/moderator', '/webmaster', '/administrator',
            '/admin1', '/admin2', '/admin3', '/admin4', '/admin5',
            '/administrator1', '/administrator2', '/administrator3',
            '/administrator4', '/administrator5', '/moderator1',
            '/moderator2', '/moderator3', '/moderator4', '/moderator5',
            '/webmaster1', '/webmaster2', '/webmaster3', '/webmaster4',
            '/webmaster5', '/user1', '/user2', '/user3', '/user4',
            '/user5', '/member1', '/member2', '/member3', '/member4',
            '/member5', '/account1', '/account2', '/account3', '/account4',
            '/account5', '/profile1', '/profile2', '/profile3', '/profile4',
            '/profile5', '/dashboard1', '/dashboard2', '/dashboard3',
            '/dashboard4', '/dashboard5', '/cp1', '/cp2', '/cp3', '/cp4',
            '/cp5', '/cpanel1', '/cpanel2', '/cpanel3', '/cpanel4',
            '/cpanel5', '/panel1', '/panel2', '/panel3', '/panel4',
            '/panel5', '/admin-panel1', '/admin-panel2', '/admin-panel3',
            '/admin-panel4', '/admin-panel5', '/adminpanel1', '/adminpanel2',
            '/adminpanel3', '/adminpanel4', '/adminpanel5', '/adm1',
            '/adm2', '/adm3', '/adm4', '/adm5', '/mod1', '/mod2', '/mod3',
            '/mod4', '/mod5', '/webmaster1', '/webmaster2', '/webmaster3',
            '/webmaster4', '/webmaster5', '/administrator1', '/administrator2',
            '/administrator3', '/administrator4', '/administrator5'
        ]

    def check_path(self, path):
        """Check if a path exists on the target"""
        url = urljoin(self.target_url, path)
        try:
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code != 404:
                return path, response.status_code
        except:
            pass
        return None, None

    def scan(self, threads=10):
        """Start directory bruteforcing"""
        print(termcolor.colored("\n[*] Starting directory bruteforce scan...", "cyan"))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_path = {executor.submit(self.check_path, path): path 
                            for path in self.common_paths}
            
            for future in concurrent.futures.as_completed(future_to_path):
                path, status_code = future.result()
                if path:
                    self.found_dirs.append((path, status_code))
                    print(termcolor.colored(f"[+] Found: {path} (Status: {status_code})", "green"))
        
        return self.found_dirs 