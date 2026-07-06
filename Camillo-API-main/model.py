import ipaddress
import re
from bs4 import BeautifulSoup
import requests
import whois
import urllib
import urllib.request
from datetime import datetime
import json
import csv
import time
import socket
import ssl
import os
from MLmodel import Feature_Extractor ,Url_Features
from MLmodel.API import get_prediction

global BASE_SCORE
global PROPERTY_SCORE_WEIGHTAGE
BASE_SCORE = 50  # default trust_ score of url out of 100
PROPERTY_SCORE_WEIGHTAGE = {
    'domain_rank': 0.9,
    'domain_age': 0.3,
    'is_url_shortened': 0.8,
    'hsts_support': 0.1,
    'ip_present': 0.8,
    'url_redirects': 0.2,
    'too_long_url': 0.1,
    'too_deep_url': 0.5,
    'content': 0.1
}

# Pre-load rankings and url-shorteners to avoid repeated disk reads
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOP_1M_PATH = os.path.join(BASE_DIR, 'static', 'data', 'sorted-top1million.txt')
DOMAIN_RANK_PATH = os.path.join(BASE_DIR, 'static', 'data', 'domain-rank.json')
URL_SHORTENERS_PATH = os.path.join(BASE_DIR, 'static', 'data', 'url-shorteners.txt')
LOCAL_BLOCKLIST_PATH = os.path.join(BASE_DIR, 'static', 'data', 'local-blocklist.txt')

TOP_1M_LIST = []
DOMAIN_RANK_DICT = {}
URL_SHORTENERS_LIST = []
MALICIOUS_BLOCKLIST_SET = set()

try:
    print("[INFO] Loading top 1M domains list from disk...")
    start_t = time.time()
    if os.path.exists(TOP_1M_PATH):
        with open(TOP_1M_PATH, 'r') as f:
            TOP_1M_LIST = f.read().splitlines()
        print(f"[INFO] Loaded top 1M domains list in {time.time() - start_t:.2f} seconds")
    else:
        print(f"[WARNING] Top 1M domains file not found at: {TOP_1M_PATH}")

    print("[INFO] Loading domain rank json from disk...")
    start_t = time.time()
    if os.path.exists(DOMAIN_RANK_PATH):
        with open(DOMAIN_RANK_PATH, 'r') as f:
            DOMAIN_RANK_DICT = json.load(f)
        print(f"[INFO] Loaded domain rank json in {time.time() - start_t:.2f} seconds")
    else:
        print(f"[WARNING] Domain rank json file not found at: {DOMAIN_RANK_PATH}")

    if os.path.exists(URL_SHORTENERS_PATH):
        with open(URL_SHORTENERS_PATH, 'r') as f:
            URL_SHORTENERS_LIST = f.read().splitlines()
    else:
        print(f"[WARNING] URL shorteners list not found at: {URL_SHORTENERS_PATH}")
except Exception as e:
    print(f"[ERROR] Failed to load data lists in model.py: {e}")

def load_or_update_blocklist():
    global MALICIOUS_BLOCKLIST_SET
    start_t = time.time()
    
    # 1. Load from local cache first if it exists
    if os.path.exists(LOCAL_BLOCKLIST_PATH):
        try:
            with open(LOCAL_BLOCKLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        MALICIOUS_BLOCKLIST_SET.add(line.lower())
            print(f"[INFO] Loaded {len(MALICIOUS_BLOCKLIST_SET)} domains from local blocklist in {time.time() - start_t:.2f}s")
        except Exception as e:
            print(f"[ERROR] Failed to load local blocklist cache: {e}")

    # 2. Asynchronously update/pull from StevenBlack's adware/malware blocklist
    # Timeout of 3s to prevent startup hang on slow networks
    try:
        print("[INFO] Checking for blocklist updates from StevenBlack hosts...")
        update_url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        resp = requests.get(update_url, timeout=3)
        if resp.status_code == 200:
            new_domains = set()
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                        domain_val = parts[1].strip().lower()
                        if domain_val not in ('localhost', 'localhost.localdomain', 'broadcasthost'):
                            new_domains.add(domain_val)
            
            if new_domains:
                MALICIOUS_BLOCKLIST_SET = new_domains
                # Ensure the parent directory exists
                os.makedirs(os.path.dirname(LOCAL_BLOCKLIST_PATH), exist_ok=True)
                with open(LOCAL_BLOCKLIST_PATH, 'w', encoding='utf-8') as f:
                    for d in sorted(MALICIOUS_BLOCKLIST_SET):
                        f.write(d + '\n')
                print(f"[INFO] Successfully updated local blocklist cache with {len(MALICIOUS_BLOCKLIST_SET)} domains in {time.time() - start_t:.2f}s")
        else:
            print(f"[WARNING] Blocklist update skipped. HTTP Status: {resp.status_code}")
    except Exception as e:
        print(f"[INFO] Blocklist update skipped (offline/timeout): {e}")

# Run blocklist loader at startup
load_or_update_blocklist()

def check_blocklist(domain):
    domain = domain.lower()
    # Check exact matching first
    if domain in MALICIOUS_BLOCKLIST_SET:
        return True
    # Check parent domain hierarchies (e.g. sub.domain.com -> domain.com)
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        test_domain = '.'.join(parts[i:])
        if test_domain in MALICIOUS_BLOCKLIST_SET:
            return True
    return False



def fetch_url_metadata(url):
    metadata = {
        'status_code': False,
        'headers': {},
        'redirects': [],
        'content': ''
    }
    try:
        # Use a reasonable timeout and browser user-agent
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Camillo/2.0'})
        metadata['status_code'] = response.status_code
        metadata['headers'] = response.headers
        metadata['content'] = response.text
        if response.history:
            metadata['redirects'] = [resp.url for resp in response.history]
    except Exception as e:
        print(f"[ERROR] Failed to fetch URL metadata for {url}: {e}")
    return metadata

# check whether the link is active or not
def validate_url(url_or_metadata):
    if isinstance(url_or_metadata, dict):
        return url_or_metadata.get('status_code', False)
    try:
        response = requests.get(url_or_metadata, timeout=5)
        return response.status_code
    except requests.exceptions.RequestException:
        return False  # or any default value you prefer

def include_protocol(url):
    try:
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        return url

    except:
        return url

def get_full_url_for_model(partial_url):
        if partial_url.startswith('https://') or partial_url.startswith('http://'):
            pass
        else:
            # Otherwise, check if HTTPS is enabled
            try:
                response = requests.head('https://' + partial_url)
                if response.status_code == 200:
                    # If HTTPS is enabled, add 'https://'
                    partial_url = 'https://' + partial_url
                else:
                    # If HTTPS is not enabled or there's an error, add 'http://'
                    partial_url = 'http://' + partial_url
            except requests.RequestException:
                # If HTTPS is not enabled or there's an error, add 'http://'
                partial_url = 'http://' + partial_url
        if not partial_url.endswith('/'):
            partial_url += '/'

        return partial_url

# get domain rank if it exists in top 1M list
def get_domain_rank(domain):
    is_in_top1million = binary_search(TOP_1M_LIST, domain)

    if is_in_top1million == 1:
        rank = DOMAIN_RANK_DICT.get(domain, 0)
        return int(rank)
    else:
        return 0


# binary search
def binary_search(arr, x):
    low = 0
    high = len(arr) - 1
    while low <= high:
        mid = (low + high) // 2
        if arr[mid] == x:
            return 1
        elif arr[mid] < x:
            low = mid + 1
        else:
            high = mid - 1
    return 0

# get whois data of domain
def whois_data(domain):
    try:
        whois_data = whois.whois(domain)
        creation_date = whois_data.creation_date
        data = {}

        if type(creation_date) is list:
            creation_date = creation_date[0]
            whois_data['creation_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.creation_date]
        # else:
        #     whois_data['creation_date'] = whois_data.creation_date.strftime('%Y-%m-%d %H:%M:%S')

        if type(whois_data.updated_date) is list:
            whois_data['updated_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.updated_date]
        # else:
        #     whois_data['updated_date'] = whois_data.updated_date.strftime('%Y-%m-%d %H:%M:%S')

        if type(whois_data.expiration_date) is list:
            whois_data['expiration_date'] = [d.strftime('%Y-%m-%d %H:%M:%S') for d in whois_data.expiration_date]
        # else:
        #     whois_data['expiration_date'] = whois_data.expiration_date.strftime('%Y-%m-%d %H:%M:%S')


        if creation_date == None:
            age = 'Not Given'
        else:
            age = (datetime.now() - creation_date).days / 365 

        for prop in whois_data:
            if type(whois_data[prop]) is list:
                data[pascal_case(prop)] = ', '.join(whois_data[prop])
            else:
                data[pascal_case(prop)] = whois_data[prop]

        return {'age':age, 'data':data}

    except Exception as e:
        print(f"Error: {e}")
        return False


def pascal_case(s):
    result = s.replace('_',' ').title()
    return result


# check for HSTS support
def hsts_support(url_or_metadata): # url should be http / https as prefix
    try:
        if isinstance(url_or_metadata, dict):
            headers = url_or_metadata.get('headers', {})
            return 1 if 'Strict-Transport-Security' in headers else 0
        response = requests.get(url_or_metadata, timeout=5)
        headers = response.headers
        if 'Strict-Transport-Security' in headers:
            return 1
        else:
            return 0
    except:
        return 0


# check for URL shortening services
def is_url_shortened(domain): 
    try:
        for service in URL_SHORTENERS_LIST:
            if service in domain:
                return 1
        return 0
    except:
        return 0


# check if an IP is present in the URL
def ip_present(url):
    try:
        ipaddress.ip_address(url)
        result = 1
    except:
        result = 0
    return result


# check for website redirects
def url_redirects(url_or_metadata):
    try:
        if isinstance(url_or_metadata, dict):
            return url_or_metadata.get('redirects', [])
        response = requests.get(url_or_metadata, timeout=5)
        if len(response.history) > 1:
            # URL is redirected
            url_history = [] # returns array of redirected URLs
            for resp in response.history:
                url_history.append(resp.url)
            return url_history
        else:
            return []  # Return an empty list when there are no redirects
    except Exception as e:
        # print(f"Error: {e}")
        return [] 

# check whether the URL is too long 
def too_long_url(url):
    if len(url) > 75:
        return 1
    else:
        return 0


# check whether the URL is too deep 
def too_deep_url(url):
    slashes = -2 # to skip first two slashes after protocol, i.e. https://
    for i in url:
        if i == '/':
            slashes += 1

    if slashes > 5:
        return 1
    else:
        return 0



# check whether the URL is having 
def content_check(url_or_metadata):
    try:
        if isinstance(url_or_metadata, dict):
            content = url_or_metadata.get('content', '')
            if not content:
                return 0
            soup = BeautifulSoup(content, 'html.parser')
        else:
            response = requests.get(url_or_metadata, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')

        result = {'onmouseover':0, 'right-click':0, 'form':0, 'iframe':0, 'login':0, 'popup':0}

        # check if onmouseover is enabled
        if soup.find(onmouseover=True):
            result['onmouseover'] = 1


        # check if right-click is disabled
        if soup.find_all('body', {'oncontextmenu': 'return false;'}):
            result['right-click'] = 1


        # check if there are any forms present
        if soup.find_all('form'):
            result['form'] = 1

        # check if there are any iframes present
        if soup.find_all('iframe'):
            result['iframe'] = 1

        # check if there are any login keyword present
        if soup.find_all(text=re.compile('password|email|forgotten|login')):
            result['login'] = 1

        # check if there are any pop-ups present
        if soup.find_all('div', {'class': 'popup'}):
            result['popup'] = 1
        
        return result

    except Exception as e:
        # print(f"Error: {e}")
        return 0



def phishtank_search(url):

    try:
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        response = requests.post(endpoint, data={"url": url, "format": "json"})
        data = json.loads(response.content)
        if data['results']['valid'] == True:
            return 1
        return 0

    except Exception as e:
        # print(f"Error: {e}")
        return 0


def get_ip(domain):

    try:
        ip = socket.gethostbyname(domain)
        return ip

    except Exception as e:
        print(f"Error: {e}")
        return 0



def get_certificate_details(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                cert = sslsock.getpeercert()


                # Certificate Authority (CA) information
                issuer = dict(x[0] for x in cert['issuer'])
                if 'organizationName' in issuer:
                    ca_info = issuer['organizationName']
                else:
                    ca_info = issuer['commonName']


                # Certificate validity period
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (not_after - datetime.now()).days

                # Certificate revocation status
                revoked = False
                for crl in cert.get('crlDistributionPoints', ()):
                    try:
                        crl_data = ssl.get_server_certificate((crl.split('//')[1]).split('/')[0])
                        crl_obj = ssl.load_crl_der(ssl.PEM_to_DER_cert(crl_data))
                        if crl_obj.get_revoked_certificate_by_serial_number(cert['serialNumber']):
                            revoked = True
                            break
                    except Exception:
                        pass

                # Cipher suite
                cipher = sslsock.cipher()
                cipher_suite = cipher[0]

                # SSL/TLS version
                version = sslsock.version()

                # Common name and Subject Alternative Names (SANs)
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject['commonName']
                sans = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']

                return {
                    'Issued By': ca_info,
                    'Issued To': common_name,
                    'Valid From': not_before.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    # 'sans': sans
                    'Valid Till': not_after.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'Days to Expiry': days_to_expiry,
                    'Version': version,
                    'Is Certificate Revoked': revoked,
                    'Cipher Suite': cipher_suite
                    # 'chain_info': chain_info,
                }
    except Exception as e:
        print(f"Error: {e}")
        return 0


# TEST FUNCTION TO ADD NEW URL CHECKS
def test(domain):
    
    with open('sorted-top1million.txt') as f:
        top1million = f.read().splitlines()
        
# ================== starting Model try and catching ================== #

def find_model_score(model_input):
        clean_input = get_full_url_for_model(model_input) 
        model_score = get_prediction(clean_input)
        return model_score

# res = content_check(url)
# print(res)


def calculate_trust_score(current_score, case, value):

    score = current_score

    if case == 'domain_rank':
        if value == 0:  # not in top 10L rank
            score = current_score #- (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.5)
        elif value < 100000:  # in top 1L rank
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE)
        elif value < 500000:  # in 1L - 5L rank
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.8)
        else:  # in 5L - 10L rank
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.6)
        return score

    elif case == 'domain_age':
        if isinstance(value, str) or value is None:
            # If age is not given (e.g., private WHOIS), treat as moderate risk
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE * 0.5)
        elif value < 5:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE)
        elif value >= 5 and value < 10:
            score = current_score
        elif value >= 10:
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE)
        return score

    elif case == 'is_url_shortened':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['is_url_shortened'] * BASE_SCORE)
        return score

    elif case == 'hsts_support':
        if value == 1:
            score = current_score + (PROPERTY_SCORE_WEIGHTAGE['hsts_support'] * BASE_SCORE)
        else:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['hsts_support'] * BASE_SCORE)
        return score

    elif case == 'ip_present':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['ip_present'] * BASE_SCORE)
        return score

    elif case == 'url_redirects':
        if value:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['url_redirects'] * BASE_SCORE)
        return score

    elif case == 'too_long_url':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['too_long_url'] * BASE_SCORE)
        return score

    elif case == 'too_deep_url':
        if value == 1:
            score = current_score - (PROPERTY_SCORE_WEIGHTAGE['too_deep_url'] * BASE_SCORE)
        return score

    elif case == 'content':
        if isinstance(value, dict):
            # Calculate deductions for features like right-click disabled, active onmouseover, popup divs, etc.
            deductions = 0
            if value.get('onmouseover') == 1:
                deductions += 1
            if value.get('right-click') == 1:
                deductions += 1
            if value.get('popup') == 1:
                deductions += 1
            if deductions > 0:
                score = current_score - (PROPERTY_SCORE_WEIGHTAGE['content'] * BASE_SCORE * deductions)
        return score