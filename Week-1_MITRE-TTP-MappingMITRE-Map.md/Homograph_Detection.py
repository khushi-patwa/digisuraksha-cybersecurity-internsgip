import unicodedata
import string
from urllib.parse import urlparse


standard_chars = set(string.ascii_letters + string.digits + string.punctuation + " ")
safe_invisible_chars = {'\n', '\r', '\t'}


def is_allowed_standard_char(ch):
    return ch in standard_chars


def is_suspicious(ch):
    if ch in safe_invisible_chars:
        return False
    if ch in standard_chars:
        return False
    return True


def scan_text(text):
    results = []
    for ch in text:
        if is_suspicious(ch):
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = "Unknown or Non-character"
            codepoint = f"U+{ord(ch):04X}"
            results.append((ch, name, codepoint))
    return results


def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def scan_domain(domain_or_url):
    domain = extract_domain(domain_or_url)
    return scan_text(domain)


if _name_ == "_main_":
    test_inputs = [
        "gооgle.com",          
        "facebook.com",       
        "fасebook.com",       
        "apple.com",           
        "аррӏе.com",          
        "twitter.com",        
        "twіtter.com",        
        "github.com",          
        "ɡithub.com",         
        "system32.exe",        
        "ѕystem32.exe",        
        "Password123!",       
        "Ρassword123!",        
        "user@example.com",    
        "user@ехample.com",   
        "secure-password",    
        "secure-раssword",     
        "example.net",         
        "ехample.net"         
    ]

    for test in test_inputs:
        result = scan_domain(test)
        if result:
            print(f"\nSuspicious characters found in '{test}':")
            for ch, name, codepoint in result:
                print(f"  Character: '{ch}' | Unicode: {codepoint} | Name: {name}")
        else:
            print(f"\n'{test}' is clean.")
