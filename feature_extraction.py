import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
import whois
from datetime import datetime
import time
from dateutil.parser import parse as date_parse
import requests
from bs4 import BeautifulSoup

def ambil_konten(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error saat mengambil konten: {e}")
        return None
def analisis_konten(konten):
    soup = BeautifulSoup(konten, 'html.parser')
    
    # Contoh analisis: mencari formulir yang mencurigakan
    forms = soup.find_all('form')
    if forms:
        for form in forms:
            # Cek apakah ada input dengan type 'password'
            if form.find('input', {'type': 'password'}):
                return True  # Terdeteksi potensi phishing
    
    # Cek elemen lain yang mencurigakan
    scripts = soup.find_all('script')
    for script in scripts:
        if 'eval(' in script.text or 'document.cookie' in script.text:
            return True  # Terdeteksi potensi phishing
    
    return False  # Tidak terdeteksi phishing
def deteksi_phishing(url):
    konten = ambil_konten(url)
    if konten:
        if analisis_konten(konten):
            return "Waspada Terindikasi Website Phishing"
    return "Bukan Website Phishing"

# Fungsi untuk mendapatkan waktu saat ini
def today():
    return datetime.now()

# Menghitung berapa lama waktu web dalam bulan
def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month - d2.month

# Untuk mengGenerate dataset dengan mengekstrak feature dari url
def generate_data_set(url):
    data_set = []

    # Mengconvert url yang masuk menjadi format standar
    if not re.match(r"^https?", url):
        url = "http://" + url

    print(f"Menganalisis URL: {url}")

    # Menyimpan respons dari URL yang diberikan
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        print(f"Error saat mengakses URL: {e}")
        response = ""
        soup = -999

    # Mengekstrak domain dari URL yang diberikan
    try:
        domain = re.findall(r"://([^/]+)/?", url)[0]
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
    except:
        domain = ""
        print("Gagal mengekstrak domain dari URL")
        
    print(f"Domain: {domain}")

    # Meminta semua informasi tentang domain tersebut
    try:
        whois_response = whois.whois(domain)
    except Exception as e:
        print(f"Error saat mengakses WHOIS: {e}")
        whois_response = None

    try:
        rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
            "name": domain
        }, timeout=5)
    except Exception as e:
        print(f"Error saat memeriksa page rank: {e}")
        rank_checker_response = None

    # Extracts global rank of the website
    try:
        if rank_checker_response and rank_checker_response.text:
            global_rank_match = re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)
            global_rank = int(global_rank_match[0]) if global_rank_match else -1
        else:
            global_rank = -1
    except Exception as e:
        print(f"Error saat mengekstrak global rank: {e}")
        global_rank = -1

    # 1.Mempunyai IP Address
    try:
        ipaddress.ip_address(url)
        data_set.append(-1)
    except:
        data_set.append(1)

    # 2.Panjang URL
    if len(url) < 54:
        data_set.append(1)
    elif len(url) >= 54 and len(url) <= 75:
        data_set.append(0)
    else:
        data_set.append(-1)

    # 3.Memisahkan service
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        data_set.append(-1)
    else:
        data_set.append(1)

    # 4.Mempunyai simbol @
    if re.findall("@", url):
        data_set.append(-1)
    else:
        data_set.append(1)

    # 5.Mempunyai double slash redirecting 
    list_slash = [x.start(0) for x in re.finditer('//', url)]
    if len(list_slash) > 1:
        if list_slash[len(list_slash)-1] > 6:
            data_set.append(-1)
        else:
            data_set.append(1)
    else:
        data_set.append(1)

    # 6.Prefix_Suffix
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        data_set.append(-1)
    else:
        data_set.append(1)

    # 7.Mempunyai SubDomain
    if len(re.findall("\.", url)) == 1:
        data_set.append(1)
    elif len(re.findall("\.", url)) == 2:
        data_set.append(0)
    else:
        data_set.append(-1)

    # 8.SSLfinal_State
    try:
        if response and response.text:
            data_set.append(1)
        else:
            data_set.append(-1)
    except:
        data_set.append(-1)

    # 9.Panjang Domain registeration
    try:
        expiration_date = whois_response.expiration_date
        registration_length = 0
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = min(expiration_date)
            today_date = today()
            registration_length = abs((expiration_date - today_date).days)

            if registration_length / 365 <= 1:
                data_set.append(-1)
            else:
                data_set.append(1)
        else:
            data_set.append(-1)
    except:
        data_set.append(-1)

    # 10.Favicon
    if soup == -999:
        data_set.append(-1)
    else:
        try:
            favicon_found = False
            for head in soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    if 'icon' in link.get('rel', []) or 'shortcut icon' in link.get('rel', []):
                        dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                        if url in link['href'] or len(dots) == 1 or domain in link['href']:
                            data_set.append(1)
                            favicon_found = True
                            break
                        else:
                            data_set.append(-1)
                            favicon_found = True
                            break
                if favicon_found:
                    break
            if not favicon_found:
                data_set.append(-1)
        except:
            data_set.append(-1)

    #11. port
    try:
        port = domain.split(":")[1]
        if port:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(1)

    #12. HTTPS_token
    if re.findall(r"^https://", url):
        data_set.append(1)
    else:
        data_set.append(-1)

    #13. Request_URL
    i = 0
    success = 0
    if soup == -999:
        data_set.append(-1)
    else:
        try:
            for img in soup.find_all('img', src=True):
               dots = [x.start(0) for x in re.finditer('\.', img['src'])]
               if url in img['src'] or domain in img['src'] or len(dots) == 1:
                  success = success + 1
               i = i + 1

            for audio in soup.find_all('audio', src=True):
               dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
               if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                  success = success + 1
               i = i + 1

            for embed in soup.find_all('embed', src=True):
               dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
               if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                  success = success + 1
               i = i + 1

            for iframe in soup.find_all('iframe', src=True):
               dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
               if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                  success = success + 1
               i = i + 1

            if i > 0:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    data_set.append(1)
                elif (percentage >= 22.0) and (percentage < 61.0):
                    data_set.append(0)
                else:
                    data_set.append(-1)
            else:
                data_set.append(1)
        except:
            data_set.append(1)

    #14. URL_of_Anchor
    percentage = 0
    i = 0
    unsafe = 0
    if soup == -999:
        data_set.append(-1)
    else:
        try:
            for a in soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            if i > 0:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    data_set.append(1)
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    data_set.append(0)
                else:
                    data_set.append(-1)
            else:
                data_set.append(1)
        except:
            data_set.append(1)

    #15. Links_in_tags
    i = 0
    success = 0
    if soup == -999:
        data_set.append(-1)
    else:
        try:
            for link in soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if url in link['href'] or domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for script in soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if url in script['src'] or domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            if i > 0:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    data_set.append(1)
                elif ((percentage >= 17.0) and (percentage < 81.0)):
                    data_set.append(0)
                else:
                    data_set.append(-1)
            else:
                data_set.append(1)
        except:
            data_set.append(1)

    #16. SFH
    found_form = False
    for form in soup.find_all('form', action=True):
        found_form = True
        if form['action'] == "" or form['action'] == "about:blank":
            data_set.append(-1)
        elif url not in form['action'] and domain not in form['action']:
            data_set.append(0)
        else:
            data_set.append(1)
        break
    
    if not found_form:
        data_set.append(1)

    #17. Submitting_to_email
    if response == "":
        data_set.append(-1)
    else:
        try:
            if re.findall(r"[mail\(\)|mailto:?]", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)
        except:
            data_set.append(-1)

    #18. Abnormal_URL
    if response == "":
        data_set.append(-1)
    else:
        try:
            if response.text == "":
                data_set.append(1)
            else:
                data_set.append(-1)
        except:
            data_set.append(-1)

    #19. Redirect
    if response == "":
        data_set.append(-1)
    else:
        try:
            if len(response.history) <= 1:
                data_set.append(-1)
            elif len(response.history) <= 4:
                data_set.append(0)
            else:
                data_set.append(1)
        except:
            data_set.append(-1)

    #20. on_mouseover
    if response == "":
        data_set.append(-1)
    else:
        try:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)
        except:
            data_set.append(-1)

    #21. RightClick
    if response == "":
        data_set.append(-1)
    else:
        try:
            if re.findall(r"event.button ?== ?2", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)
        except:
            data_set.append(-1)

    #22. popUpWidnow
    if response == "":
        data_set.append(-1)
    else:
        try:
            if re.findall(r"alert\(", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)
        except:
            data_set.append(-1)

    #23. Iframe
    if response == "":
        data_set.append(-1)
    else:
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                data_set.append(1)
            else:
                data_set.append(-1)
        except:
            data_set.append(-1)

    #24. Umur dari domain link
    try:
        if whois_response and whois_response.creation_date:
            creation_date = whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = min(creation_date)
            
            if diff_month(today(), creation_date) >= 6:
                data_set.append(-1)
            else:
                data_set.append(1)
        else:
            data_set.append(-1)
    except:
        data_set.append(-1)

    #25. DNSRecord
    try:
        if whois_response and whois_response.expiration_date:
            expiration_date = whois_response.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = min(expiration_date)
            
            today_date = today()
            registration_length = abs((expiration_date - today_date).days)

            if registration_length / 365 <= 1:
                data_set.append(-1)
            else:
                data_set.append(1)
        else:
            data_set.append(-1)
    except:
        data_set.append(-1)

    #26. web_traffic
    # API Alexa tidak lagi tersedia, kita nilai 1 langsung
    data_set.append(1)

    #27. Page_Ranking
    try:
        if global_rank > 0 and global_rank < 100000:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(1)

    #28. Google_Index
    # Batasi penggunaan Google Search API
    try:
        # Gunakan pendekatan alternatif
        # Karena googlesearch sering dibatasi, kita asumsikan situs terdaftar
        data_set.append(1)
    except:
        data_set.append(1)

    #29. Links_pointing_to_page
    if response == "":
        data_set.append(-1)
    else:
        try:
            number_of_links = len(re.findall(r"<a href=", response.text))
            if number_of_links == 0:
                data_set.append(1)
            elif number_of_links <= 2:
                data_set.append(0)
            else:
                data_set.append(-1)
        except:
            data_set.append(-1)

    #30. Statistical_report
    url_match = re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    try:
        ip_address = socket.gethostbyname(domain)
        ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                           '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                           '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                           '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                           '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                           '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
        if url_match:
            data_set.append(-1)
        elif ip_match:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(1)
        print ('Gagal memeriksa IP address, kemungkinan masalah koneksi internet')

#Terindikasi web aman
def is_trusted_website(domain):
    """
    Check if the domain is in our list of trusted websites.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        bool: True if the domain is trusted, False otherwise
    """
    # List domain terpercaya patterns
    trusted_domains = [
        # Major search engines
        'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com',
        # Social media
        'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 
        'pinterest.com', 'reddit.com', 'tumblr.com', 'quora.com', 'tiktok.com',
        # E-commerce
        'amazon.com', 'ebay.com', 'walmart.com', 'aliexpress.com', 'shopee.com',
        'lazada.com', 'tokopedia.com', 'bukalapak.com', 'blibli.com',
        # Messenger and communication
        'whatsapp.com', 'telegram.org', 'skype.com', 'zoom.us', 'teams.microsoft.com',
        'discord.com', 'slack.com', 'line.me',
        # Ride sharing and food delivery
        'uber.com', 'grab.com', 'gojek.com', 'lyft.com', 'doordash.com',
        'foodpanda.com', 'deliveroo.com',
        # Productivity and cloud
        'microsoft.com', 'apple.com', 'icloud.com', 'drive.google.com', 'dropbox.com',
        'office.com', 'gmail.com', 'outlook.com', 'protonmail.com',
        # Streaming services
        'youtube.com', 'netflix.com', 'spotify.com', 'disney.com', 'hulu.com',
        'primevideo.amazon.com', 'twitch.tv', 'vimeo.com',
        # News and information
        'cnn.com', 'bbc.com', 'nytimes.com', 'theguardian.com', 'reuters.com',
        'wikipedia.org', 'kompas.com', 'detik.com',
        # Payment services
        'paypal.com', 'visa.com', 'mastercard.com', 'stripe.com', 'gopay.co.id',
        'ovo.id', 'dana.id'
    ]
    
    # Bersihkan domain untuk perbandingan
    domain = domain.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # periksa apakah domain secara tepat cocok atau merupakan subdomain dari domain yang tepercaya
    for trusted in trusted_domains:
        if domain == trusted or domain.endswith('.' + trusted):
            return True
    
    return False


# Contoh bagaimana mengintegrasikan ini dengan kode Anda yang sudah ada
def generate_data_set(url):
    data_set = []
    
    # Kode yang ada untuk ekstraksi fitur
    # ...
    
    # Extract domain dari URL yang telah diberikan
    try:
        domain = re.findall(r"://([^/]+)/?", url)[0]
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
    except:
        domain = ""
        print("Gagal mengekstrak domain dari URL")
    
    # Periksa apakah ini adalah situs web terpercaya (tambahkan ini awal)
    is_trusted = is_trusted_website(domain)
    if is_trusted:
        print(f"Domain {domain} terdeteksi sebagai website tepercaya")
        # Kamu bisa lakukan juga:
        # 1. Return early with a special trusted flag
        # 2. Continue with analysis but add a trusted flag feature
        # 3. Set all features to indicate "safe" (-1 values)
        
        # Option for early return with trusted flag:
        # return [-1] * 30 + [1]  # All safe features + trusted flag
    
    # Lanjutkan dengan ekstraksi fitur yang sudah ada
    
    # Tambahkan situs web tepercaya sebagai fitur baru di akhir
    data_set.append(1 if is_trusted else -1)
    
    return data_set


# Untuk digunakan dengan machine learning model
def predict_with_trusted_sites(url):
    """
    Predict if a URL is safe, with a bypass for trusted sites.
    
    Args:
        url (str): URL to check
        
    Returns:
        str: "safe" or "phishing"
    """
    # Extract domain
    try:
        domain = re.findall(r"://([^/]+)/?", url)[0]
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
            
        # Quick check untuk trusted sites
        if is_trusted_website(domain):
            return "safe"
    except:
        pass
    
    # If not trusted, proceed with full feature extraction and ML prediction
    features = generate_data_set(url)
    # prediction = your_ml_model.predict([features])
    # return "safe" if prediction == 1 else "phishing"
    
    # Untuk keperluan demonstration:
    safe_count = features.count(1)
    phishing_count = features.count(-1)
    return "safe" if safe_count > phishing_count else "phishing"

    print(f"Dataset lengkap: {data_set}")
    print(f"Jumlah fitur: {len(data_set)}")
    return data_set