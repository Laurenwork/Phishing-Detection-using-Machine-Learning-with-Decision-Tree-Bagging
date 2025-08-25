import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
import tldextract
import socket
import whois
from datetime import datetime
import time

def is_phishing(domain_age_days, content_analysis):
    score = 0
    
    # Umur Domain
    if domain_age_days < 7:
        score += 1

    # Indikasi Konten
    if content_analysis['has_login_form']:
        score += 1
    if content_analysis['uses_brand_logo']:
        score += 1
    if content_analysis['uses_suspicious_keywords']:
        score += 1

    return score >= 2  # Threshold bisa disesuaikan
result = {
  'phishing': False,
  'reason': ['Domain is very new (1 days old)'],
  'content_analysis': {
    'has_login_form': True,
    'uses_brand_logo': True,
  }
}

def analyze_content(url):
    """
    Analyze website content to detect phishing indicators.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        tuple: (is_phishing_content, confidence_score, reasons)
    """
    try:
        # Normalisasi URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Mendapatkan domain informasi
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if extracted.subdomain:
            full_domain = f"{extracted.subdomain}.{domain}"
        else:
            full_domain = domain
            
        # Mendapatkan konten web
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        
        # Initialize counters and flags
        suspicious_indicators = 0
        total_indicators = 12  # Total number of checks we perform
        reasons = []
        
        # 1. Mengecek apakah ada formulir login
        login_forms = False
        forms = soup.find_all('form')
        for form in forms:
            password_inputs = form.find_all('input', {'type': 'password'})
            if password_inputs:
                login_forms = True
                # Mengecek apakah formulir login mengirimkan data ke domain lain
                if form.has_attr('action'):
                    action_url = form['action']
                    if action_url and not action_url.startswith('#') and not action_url.startswith('/'):
                        # Mengecek apakah formulir login akan menggirim data ke domain lain
                        try:
                            action_domain = tldextract.extract(urllib.parse.urljoin(url, action_url))
                            action_domain = f"{action_domain.domain}.{action_domain.suffix}"
                            if action_domain != domain:
                                suspicious_indicators += 1
                                reasons.append(f"Login form submits to external domain: {action_domain}")
                        except:
                            pass
        
        # 2. Mengecek untuk peniruan merek dari brand berikut
        popular_brands = [
            'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 
            'instagram', 'netflix', 'bank', 'ebay', 'outlook', 'office365',
            'linkedin', 'dropbox', 'gmail', 'yahoo', 'blockchain', 'bitcoin',
            'coinbase', 'wellsfargo', 'chase', 'citibank', 'bankofamerica',
            'hsbc', 'barclays', 'santander', 'binance', 'coinmarketcap'
        ]
        
        page_text = soup.get_text().lower()
        title_text = soup.title.string.lower() if soup.title else ""
        
        # Periksa apakah domain mengandung nama merek tetapi bukan yang resmi
        for brand in popular_brands:
            if brand in extracted.domain.lower() and not is_official_domain(domain, brand):
                suspicious_indicators += 1
                reasons.append(f"Domain contains brand name '{brand}' but appears unofficial")
                break
                
        # Periksa jika judul/konten menyebutkan merek yang tidak ada dalam domain
        for brand in popular_brands:
            brand_in_content = brand in page_text or brand in title_text
            brand_not_in_domain = brand not in extracted.domain.lower()
            has_login_form = login_forms
            
            if brand_in_content and brand_not_in_domain and has_login_form:
                suspicious_indicators += 1
                reasons.append(f"Page mentions '{brand}' with login form but uses different domain")
                break
        
        # 3. Periksa klaim keamanan di domain/URL
        security_terms = ['secure', 'login', 'signin', 'verify', 'verification', 'authenticate', 'update', 'confirm']
        for term in security_terms:
            if term in extracted.domain.lower() or term in urllib.parse.unquote(url).lower():
                suspicious_indicators += 1
                reasons.append(f"URL contains security term '{term}' which is common in phishing")
                break
        
        # 4. Periksa penggunaan bahasa keamanan yang berlebihan
        security_phrases = [
            'verify your account', 'confirm your details', 'unusual activity',
            'security alert', 'account suspended', 'limited access', 'unusual sign-in activity',
            'expired password', 'update your payment', 'verify your identity',
            'account verification required', 'suspicious activity detected'
        ]
        
        security_phrase_count = 0
        for phrase in security_phrases:
            if phrase in page_text:
                security_phrase_count += 1
                
        if security_phrase_count >= 2:
            suspicious_indicators += 1
            reasons.append(f"Found {security_phrase_count} suspicious security phrases")
        
        # 5. Periksa teknik obfuscation URL
        #teknik pemrograman di mana kode sengaja dikaburkan untuk mencegah rekayasa terbalik dan mengirimkan kode yang tidak jelas kepada siapa pun selain programmer.
        if '@' in url or '%40' in url:
            suspicious_indicators += 1
            reasons.append("URL contains '@' character or encoded equivalent")
            
        # 6. Periksa untuk eksfiltrasi data melalui JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.string if script.string else ""
            if script_content:
                # Cari akses document.cookie yang dikombinasikan dengan komunikasi eksternal
                if ('document.cookie' in script_content or 'localStorage' in script_content) and \
                   ('fetch(' in script_content or 'XMLHttpRequest' in script_content or '.ajax' in script_content):
                    suspicious_indicators += 3
                    reasons.append("JavaScript attempts to access cookies and send data externally")
                    break
        
        # 7. Periksa bidang kata sandi + tidak ada SSL
        if login_forms and not url.startswith('https://'):
            suspicious_indicators += 1
            reasons.append("Login form detected but site doesn't use HTTPS")
        
        # 8. Periksa tautan yang menyesatkan
        links = soup.find_all('a', href=True)
        misleading_link_count = 0
        
        for link in links:
            href = link.get('href', '')
            # Skip empty, fragment, and relative links
            if not href or href.startswith('#') or href.startswith('/'):
                continue
                
            link_text = link.get_text().strip().lower()
            
            try:
                # Periksa apakah teks tautan menyarankan satu domain tetapi mengarah ke domain lain.
                for brand in popular_brands:
                    if brand in link_text:
                        link_domain = tldextract.extract(urllib.parse.urljoin(url, href))
                        link_domain = f"{link_domain.domain}.{link_domain.suffix}"
                        if brand not in link_domain and not is_official_domain(link_domain, brand):
                            misleading_link_count += 1
            except:
                pass
                
        if misleading_link_count >= 2:
            suspicious_indicators += 1
            reasons.append(f"Found {misleading_link_count} misleading links with brand names")
        
        # 9. Periksa apakah ada persyaratan keamanan kata sandi yang berlebihan
        password_req_texts = [
            "must contain at least", "password requirements", 
            "uppercase", "lowercase", "special character",
            "password policy", "password rules"
        ]
        
        password_req_count = 0
        for req in password_req_texts:
            if req in page_text:
                password_req_count += 1
                
        if password_req_count >= 3 and login_forms:
            suspicious_indicators += 1
            reasons.append("Excessive password requirements may indicate credential harvesting")
        
        # 10. Periksa tanda-tanda apakah ini adalah situs web alat keamanan
        security_tool_indicators = [
            'virus scan', 'malware detection', 'security scanner', 'threat intelligence',
            'antivirus', 'dmarc analyzer', 'phishing protection', 'security check',
            'url scanner', 'domain health', 'spf record', 'dkim record', 'dns tools',
            'security assessment', 'cyber security', 'virus total', 'domain analysis'
        ]
        
        security_tool_count = 0
        for indicator in security_tool_indicators:
            if indicator in page_text.lower():
                security_tool_count += 1
                
        # Jika terdapat banyak indikator alat keamanan dan memiliki SSL/umur domain yang baik, kemungkinan besar itu sah dan aman.
        is_security_tool = security_tool_count >= 3
        
        # 11. Check for domain age (use whois)Periksa untuk umur domain menggunakan who is(website informasi mengenai semua tentang website)
        domain_age_ok = True
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                domain_age_days = (datetime.now() - creation_date).days
                if domain_age_days < 30:  # Domain kurang dari 30 hari
                    suspicious_indicators += 1
                    domain_age_ok = False
                    reasons.append(f"Domain is very new ({domain_age_days} days old)")
        except:
            # IJika whois gagal, kita tidak bisa menentukan umur
            pass
            
        # 12. Periksa elemen tersembunyi untuk mengumpulkan data
        hidden_fields = soup.find_all('input', {'type': 'hidden'})
        suspicious_hidden_fields = 0
        
        for field in hidden_fields:
            field_name = field.get('name', '').lower()
            sensitive_names = ['pass', 'user', 'email', 'account', 'card', 'credit', 'ssn', 'social']
            
            if any(sensitive in field_name for sensitive in sensitive_names):
                suspicious_hidden_fields += 1
                
        if suspicious_hidden_fields >= 2:
            suspicious_indicators += 1
            reasons.append(f"Found {suspicious_hidden_fields} hidden fields collecting sensitive data")
        
        # Kasus khusus: jika itu adalah alat keamanan, kurangi skor kecurigaan
        if is_security_tool and domain_age_ok and url.startswith('https://'):
            suspicious_indicators = max(0, suspicious_indicators - 2)
            reasons.append("Website appears to be a legitimate security tool")
        
        # Hitung score kepercayaan (0-100%)
        confidence_score = (suspicious_indicators / total_indicators) * 100
        
        # Mententukan jika itu phishing bedasarkan threshold
        is_phishing_content = confidence_score >= 25  # 25% threshold
        
        return is_phishing_content, confidence_score, reasons
        
    except Exception as e:
        # Jika analisis gagal, mengambil hasil lebih hatihati
        return True, 50, [f"Content analysis failed: {str(e)}"]

def is_official_domain(domain, brand):
    """Check if a domain is likely the official one for a brand"""
    official_domains = {
        'paypal': ['paypal.com'],
        'apple': ['apple.com', 'icloud.com'],
        'google': ['google.com', 'gmail.com', 'youtube.com'],
        'microsoft': ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr'],
        'facebook': ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com'],
        'netflix': ['netflix.com'],
        'bank': [], # Sangat general, ditanganani terpisah
        'ebay': ['ebay.com', 'ebay.co.uk', 'ebay.ca', 'ebay.de'],
        'dropbox': ['dropbox.com'],
        'yahoo': ['yahoo.com'],
        'wellsfargo': ['wellsfargo.com'],
        'chase': ['chase.com'],
        'hsbc': ['hsbc.com'],
        'binance': ['binance.com', 'binance.us'],
        'coinbase': ['coinbase.com']
    }
    
    # Jika kita memiliki domain resmi yang terdaftar untuk merek ini
    if brand in official_domains:
        return any(domain == od or domain.endswith('.' + od) for od in official_domains[brand])
    
    # Untuk istilah umum seperti 'bank', periksa apakah itu adalah domain bank yang terkenal.
    if brand == 'bank':
        known_banks = ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 
                       'capitalone.com', 'usbank.com', 'pnc.com', 'tdbank.com']
        return any(domain == bank or domain.endswith('.' + bank) for bank in known_banks)
        
    # Secara default diatur ke False untuk merek yang tidak diketahui
    return False

def is_security_tool_website(url):
    """
    Check if a URL belongs to a known security tool or service.
    
    Args:
        url (str): The URL to check
        
    Returns:
        bool: True if it's a security tool website
    """
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    
    known_security_tools = [
        'virustotal.com',
        'easydmarc.com',
        'mxtoolbox.com',
        'urlscan.io',
        'dnschecker.org',
        'securitytrails.com',
        'shodan.io',
        'phishtank.org',
        'threatminer.org',
        'wpscan.com',
        'sslshopper.com',
        'dnsdumpster.com',
        'censys.io',
        'crt.sh',
        'dnslytics.com',
        'robtex.com',
        'spyse.com',
        'whoisxmlapi.com',
        'metadefender.opswat.com',
        'malwarebytes.com',
        'hybrid-analysis.com',
        'appscan.io',
        'haveibeenpwned.com',
        'securityheaders.com',
        'ssllabs.com',
        'threatcrowd.org',
        'threatintelligenceplatform.com',
        'urlvoid.com',
        'virusradar.com',
        'zulu.zscaler.com',
        'ipvoid.com',
        'emailverifier.com',
        'emailrep.io',
        'phishinginitiative.fr',
        'stopbadware.org',
        'app.webinspector.com',
        'phishcheck.me',
        'phishtank.com',
        'stopforumspam.com'
    ]
    
    return domain in known_security_tools

def check_phishing_content(url):
    """
    Main function to check if a website's content indicates phishing
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Results of the analysis including is_phishing, score, and reasons
    """
    # Pertama periksa apakah itu alat keamanan yang dikenal
    if is_security_tool_website(url):
        return {
            "is_phishing": False,
            "score": 0,
            "message": "Bukan Website Phishing",
            "reasons": ["Website is a known security tool/service"]
        }
    
    # Jika tidak, lakukan analisis konten
    is_phishing, score, reasons = analyze_content(url)
    
    return {
        "is_phishing": is_phishing,
        "score": score,
        "message": "Waspada Terindikasi Website Phishing" if is_phishing else "Bukan Website Phishing",
        "reasons": reasons
    }