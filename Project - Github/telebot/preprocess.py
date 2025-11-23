import re
import socket
import requests
import dns.resolver
from functools import lru_cache
import urllib.parse
import tldextract
from urllib.parse import urlparse
from dotenv import load_dotenv
import os

load_dotenv()
key = os.getenv("API_KEY") 

@lru_cache(maxsize=10000)
def dns_record(domain):
    try:
        # Set timeout for DNS query
        dns.resolver.timeout = 2.0
        dns.resolver.lifetime = 2.0

        nameservers = dns.resolver.resolve(domain, 'NS')
        if len(nameservers) > 0:
            return 0
        else:
            return 1
    except Exception:
        return 1

# Gets page rank with proper timeout, returns value of -1 if unavailable
def page_rank(key, domain):
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(
            url,
            headers={'API-OPR': key},
            timeout=3
        )
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except Exception:
        return -1
# @title
import re
import socket

HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images',
         'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins',
         'signin', 'view']

# Calculate ratio of digits in URL
def ratio_digits_url(url):
    if len(url) == 0:
        return 0
    return len(re.sub("[^0-9]", "", url)) / len(url)

# Calculate ratio of digits in hostname
def ratio_digits_host(hostname):
    if len(hostname) == 0:
        return 0
    return len(re.sub("[^0-9]", "", hostname)) / len(hostname)

# Obtain URL length
def length_url(url):
    return len(url)

# Obtain hostname length
def length_hostname(hostname):
    return len(hostname)

# Check if URL uses shortening services
def shortening_service(full_url):
    match = re.search(
        r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|'
        r'tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|'
        r'url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|'
        r'BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|'
        r'fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|'
        r'rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|'
        r'adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|'
        r'bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|'
        r'yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|'
        r'vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net',
        full_url
    )
    return 1 if match else 0

# Count the number of "@"
def count_at(base_url):
    return base_url.count('@')

# Count the number of ";"
def count_semicolumn(url):
    return url.count(';')

# Count the number of "&"
def count_and(base_url):
    return base_url.count('&')

# Count the number of "?"
def count_qm(base_url):
    return base_url.count('?')

# Count the number of "-"
def count_hyphens(base_url):
    return base_url.count('-')

# Count the number of "."
def count_dots(hostname):
    return hostname.count('.')

# Obtain longest word length from hostname
def longest_word_length_host(words_list):
    if not words_list or len(words_list) == 0:
        return 0
    return max(len(word) for word in words_list)

# Obtain shortest word length from hostname
def shortest_word_length_host(words_list):
    if not words_list or len(words_list) == 0:
        return 0
    return min(len(word) for word in words_list)

# Obtain longest word length from URL path
def longest_word_length_path(words_list):
    if not words_list or len(words_list) == 0:
        return 0
    return max(len(word) for word in words_list)

# Count phishing hints (using the HINTS list) in the URL path
def phish_hints(url_path):
    count = 0
    url_lower = url_path.lower()
    for hint in HINTS:
        count += url_lower.count(hint)
    return count

# Check if TLD appears in subdomain
def tld_in_subdomain(tld, subdomain):
    if subdomain.count(tld) > 0:
        return 1
    return 0

# Check for prefix-suffix pattern with hyphen
def prefix_suffix(url):
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        return 1
    else:
        return 0
    
# Check if URL/IP is in known malicious list
def statistical_report(url, domain):
    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|'
        r'hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
        url
    )
    try:
        ip_address = socket.gethostbyname(domain)
        ip_match = re.search(
            r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|'
            r'192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|'
            r'46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|'
            r'46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|'
            r'64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|'
            r'107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|'
            r'52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|'
            r'67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|'
            r'175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|'
            r'43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
            r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|'
            r'199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|'
            r'62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|'
            r'195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|'
            r'172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|'
            r'198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|'
            r'52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
            r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|'
            r'78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|'
            r'37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
            ip_address
        )
        if url_match or ip_match:
            return 1
        else:
            return 0
    except:
        return 2

# Suspicious TLDs list
SUSPICIOUS_TLDS = [
    'fit', 'tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu',
    'online', 'click', 'country', 'stream', 'download', 'xin', 'racing',
    'jetzt', 'ren', 'mom', 'party', 'review', 'trade', 'accountants',
    'science', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
    'accountant', 'realtor', 'top', 'christmas', 'gdn', 'link', 'asia',
    'club', 'la', 'ae', 'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us',
    'or.kr', 'ce.ke', 'audio', 'gob.pe', 'gov.az', 'website', 'bj',
    'mx', 'media', 'sa.gov.au'
]
# Check if TLD is suspicious based on SUSPICIOUS_TLDS list
def suspicious_tld(tld):
    return 1 if tld in SUSPICIOUS_TLDS else 0

# OpenPageRank API key
load_dotenv()
key = os.getenv("API_KEY")

# Extract domain information from URL
def get_domain(url):
    o = urllib.parse.urlsplit(url)
    return o.hostname, tldextract.extract(url).domain, o.path

# Extract features from URL
def extract_features(url, status):
    """
    Args:
        url: URL to analyze
        status: Label (phishing/legitimate)
    """
    def words_raw_extraction(domain, subdomain, path):
        w_domain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
        w_subdomain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())
        w_path = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
        raw_words = w_domain + w_path + w_subdomain
        w_host = w_domain + w_subdomain
        raw_words = list(filter(None, raw_words))
        return raw_words, list(filter(None, w_host)), list(filter(None, w_path))

    try:
        hostname, domain, path = get_domain(url)

        # Handle None hostname
        if hostname is None:
            hostname = ''

        extracted_domain = tldextract.extract(url)
        domain = extracted_domain.domain + '.' + extracted_domain.suffix
        subdomain = extracted_domain.subdomain
        tmp = url[url.find(extracted_domain.suffix):len(url)]
        pth = tmp.partition("/")
        path = pth[1] + pth[2]
        words_raw, words_raw_host, words_raw_path = words_raw_extraction(
            extracted_domain.domain, subdomain, pth[2]
        )
        tld = extracted_domain.suffix
        parsed = urlparse(url)
        scheme = parsed.scheme

        # Build feature row
        row = [
            url,
            # URL-based features
            length_url(url),
            length_hostname(hostname),
            count_dots(url),
            count_hyphens(url),
            count_at(url),
            count_qm(url),
            count_and(url),
            count_semicolumn(url),
            ratio_digits_url(url),
            ratio_digits_host(hostname),
            tld_in_subdomain(tld, subdomain),
            prefix_suffix(url),
            shortening_service(url),
            shortest_word_length_host(words_raw_host),
            longest_word_length_host(words_raw_host),
            longest_word_length_path(words_raw_path),
            phish_hints(url),
            suspicious_tld(tld),
            statistical_report(url, domain),
            # External-based features
            dns_record(domain),
            page_rank(key, domain),
        ]
        row.append(status)
        return row

    except Exception as e:
        print(f"Error processing {url}: {e}")
        return None


# Feature headers
headers = [
    'url',
    'length_url', 'length_hostname', 'nb_dots', 'nb_hyphens', 'nb_at',
    'nb_qm', 'nb_and', 'nb_semicolumn',
    'ratio_digits_url', 'ratio_digits_host', 'tld_in_subdomain',
    'prefix_suffix', 'shortening_service',
    'shortest_word_host', 'longest_word_host', 'longest_word_path',
    'phish_hints', 'suspicious_tld', 'statistical_report',
    'dns_record', 'page_rank'
]
