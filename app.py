import streamlit as st
import requests
import base64
import os
from bs4 import BeautifulSoup
import urllib3
from dotenv import load_dotenv

# --- Load environment variables ---
load_dotenv()

# Suppress InsecureRequestWarning when verify=False is used.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(layout="centered", page_title="ThreatFilter - Spam URL Detection", initial_sidebar_state="expanded")

# --- VirusTotal API Key Handling ---
# The API key will be loaded from the .env file.
# Ensure your .env file in the same directory as app.py contains:
# VIRUSTOTAL_API_KEY="YOUR API_KEY"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    # FIX for SyntaxError: unterminated string literal
    st.error("VirusTotal API Key not found. Please ensure 'VIRUSTOTAL_API_KEY' is set in your .env file in the same directory as app.py, or as an environment variable.")
    st.stop() # This halts the Streamlit app execution at this point.

# --- Web Scraping Function to get Page Description ---
def fetch_page_description(url):
    """
    Fetches the title and meta description from a given URL.
    Handles common parsing issues and SSL verification.
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        # `verify=False` addresses the SSL: CERTIFICATE_VERIFY_FAILED error.
        response = requests.get(url, headers=headers, timeout=10, verify=False) 
        response.raise_for_status() 
        
        # Using 'html.parser' which is built-in and avoids lxml dependency issues
        soup = BeautifulSoup(response.text, 'html.parser') 
        
        title = soup.find('title')
        description_meta = soup.find('meta', attrs={'name': 'description'}) or \
                           soup.find('meta', attrs={'property': 'og:description'})
        
        page_title = title.get_text().strip() if title else "No Title Found"
        page_description = description_meta.get('content', '').strip() if description_meta else ""

        if page_description:
            return f"{page_title}: {page_description}"
        elif page_title and page_title != "No Title Found":
            return page_title 
        else:
            return "Could not determine page content from scraping (no title or description meta tag)."

    except requests.exceptions.RequestException as e:
        return f"Could not access page for description: {e}"
    except Exception as e:
        return f"Error parsing page content: {e}"

# --- VirusTotal URL Detection Function ---
def check_url_virustotal(url):
    """
    Checks a URL's safety using the VirusTotal v3 API.
    Returns (status, message, malicious_count, suspicious_count, harmless_count, undetected_count)
    Status can be: 'malicious', 'suspicious', 'safe', 'not_found', 'api_error'
    """
    if not url:
        return 'error', "No URL provided.", 0, 0, 0, 0

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY, 
        "accept": "application/json"
    }

    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(report_url, headers=headers)
        response.raise_for_status() 
        data = response.json()

        if "data" in data:
            attributes = data["data"].get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})

            malicious_count = last_analysis_stats.get("malicious", 0)
            suspicious_count = last_analysis_stats.get("suspicious", 0)
            harmless_count = last_analysis_stats.get("harmless", 0)
            undetected_count = last_analysis_stats.get("undetected", 0)
            
            if malicious_count > 0:
                message = f"Detected by {malicious_count} security vendors as malicious. Proceed with extreme caution."
                return 'malicious', message, malicious_count, suspicious_count, harmless_count, undetected_count
            
            elif suspicious_count > 0:
                message = f"Detected by {suspicious_count} security vendors as suspicious. Review this URL carefully."
                return 'suspicious', message, malicious_count, suspicious_count, harmless_count, undetected_count
            else:
                message = f"VirusTotal scan shows no malicious or suspicious flags (Harmless: {harmless_count}, Undetected: {undetected_count})."
                return 'safe', message, malicious_count, suspicious_count, harmless_count, undetected_count
        else:
            return 'not_found', "URL not found in VirusTotal's database or no recent analysis available. It might be a very new URL or not widely scanned.", 0, 0, 0, 0

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            return 'not_found', "URL not found in VirusTotal's database. It might be a very new URL.", 0, 0, 0, 0
        elif response.status_code == 400:
            return 'api_error', "Bad request to VirusTotal API. Check URL format. (HTTP 400).", 0, 0, 0, 0
        elif response.status_code == 429:
            return 'api_error', "VirusTotal API rate limit exceeded. Please wait a moment and try again. (HTTP 429).", 0, 0, 0, 0
        elif response.status_code == 401:
            return 'api_error', "VirusTotal API Key invalid or unauthorized. Please check your API key. (HTTP 401).", 0, 0, 0, 0
        else:
            return 'api_error', f"HTTP error occurred: {http_err} - Status: {response.status_code}. Please try again later.", 0, 0, 0, 0
    except requests.exceptions.ConnectionError as conn_err:
        return 'api_error', f"Network error occurred: {conn_err}. Could not connect to VirusTotal. Check your internet connection.", 0, 0, 0, 0
    except Exception as err:
        return 'api_error', f"An unexpected error occurred: {err}. Please try again.", 0, 0, 0, 0


# --- Sidebar Content ---
with st.sidebar:
    st.markdown("<h2 style='color: #E0E0E0;'>🌐 ThreatFilter Info</h2>", unsafe_allow_html=True)
    st.markdown("---")

    st.markdown("<h3 style='color: #FF6347;'>🛡️ App Information</h3>", unsafe_allow_html=True)
    st.write("This app helps you detect potentially spam or malicious URLs using the VirusTotal API.")
    st.write("It also attempts to provide a brief description of safe websites through web scraping.")
    st.markdown("---")

    st.markdown("<h3 style='color: #6495ED;'>🔍 Features</h3>", unsafe_allow_html=True)
    st.markdown("- Real-time URL threat analysis")
    st.markdown("- Automatic website content description (for safe URLs)")
    st.markdown("- Simulated user engagement metrics (reviews, estimated users)")
    st.markdown("---")

    st.markdown("<h3 style='color: #90EE90;'>💻 Tech Stack</h3>", unsafe_allow_html=True)
    st.markdown("- Python")
    st.markdown("- Streamlit")
    st.markdown("- Requests (HTTP client)")
    st.markdown("- BeautifulSoup4 (HTML parsing)")
    st.markdown("- VirusTotal API")
    st.markdown("---")
    
    st.markdown("<h3 style='color: #FFD700;'>👨‍💻 Developed by:</h3>", unsafe_allow_html=True) 
    st.markdown("[Anushka Chakraborty](https://www.linkedin.com/in/anushka-chakraborty-006881311/)", unsafe_allow_html=True) 


# --- Main Content Area ---
st.markdown("<h1 style='text-align: center; color: #FF6347;'>🛡️ ThreatFilter <span style='color: #6495ED;'>— Spam URL Detection</span></h1>", unsafe_allow_html=True)
st.markdown("---")
st.markdown("<h3 style='color: #ADD8E6;'>🔗 Enter a URL below to check if it's safe and get analysis from VirusTotal.</h3>", unsafe_allow_html=True)

url_input = st.text_input("Enter URL here", "https://www.example.com", help="e.g., https://www.google.com, https://docs.streamlit.io") 

if st.button("🔍 Check URL", use_container_width=True): 
    if url_input:
        with st.spinner("⏳ Checking URL... This may take a moment."): 
            status, message, malicious_count, suspicious_count, harmless_count, undetected_count = check_url_virustotal(url_input)

            if status == 'malicious':
                st.error("🚨 DANGER: This URL is potentially malicious!")
                st.warning(f"Detected by {malicious_count} security vendors as malicious. Proceed with extreme caution.")
                
                st.markdown("<h4 style='color: #FFD700;'>⭐ User Reviews:</h4>", unsafe_allow_html=True)
                st.markdown("- User X: 'Beware! This site caused issues on my device.'")
                st.markdown("- User Y: 'Got redirected to a weird page after clicking this link.'")
                st.markdown("- User Z: 'My antivirus blocked this URL. Stay away!'")
                st.markdown("*(Note: User reviews are simulated and not based on real data for security reasons.)*")

            elif status == 'suspicious':
                st.warning("⚠️ This URL is flagged as suspicious!")
                st.info(message) 
                st.markdown("<h4 style='color: #FFD700;'>⭐ User Reviews:</h4>", unsafe_allow_html=True)
                st.markdown("- User P: 'This site felt a bit off, proceeded with caution.'")
                st.markdown("- User Q: 'Some elements on the page seemed fishy.'")
                st.markdown("*(Note: User reviews are simulated.)*")

            elif status == 'safe':
                st.success("✅ This URL appears safe based on VirusTotal analysis.")
                st.info(message)
                
                st.subheader("🌐 Website Information:") 
                
                with st.spinner("🕸️ Fetching page description..."): 
                    page_description = fetch_page_description(url_input)
                    st.write(page_description)

                st.markdown("<h4 style='color: #90EE90;'>👥 Estimated Users: Millions of users daily (Simulated)</h4>", unsafe_allow_html=True) 
                
                st.markdown("<h4 style='color: #FFD700;'>⭐ Good Reviews (Simulated):</h4>", unsafe_allow_html=True) 
                st.markdown("- User A: 'Clean and reliable website. Highly recommended!'")
                st.markdown("- User B: 'Fast loading and great user experience.'")
                st.markdown("- User C: 'A trustworthy source for information.'")
                st.markdown("*(Note: User counts and reviews are simulated, as this data is generally not available via generic web scraping or threat APIs.)*")
                
            elif status == 'not_found':
                st.info("ℹ️ URL not found in VirusTotal's database.")
                st.warning(message) 
                st.markdown("*(This often happens for very new or unique URLs that haven't been widely scanned yet. It doesn't necessarily mean it's safe or unsafe.)*")
                
            elif status == 'api_error':
                st.error("🚫 An API Error Occurred.")
                st.exception(message) 

    else:
        st.warning("⚠️ Please enter a URL to check.") 

st.markdown("---")
st.caption("🔒 Disclaimer: This tool uses the VirusTotal API for URL analysis. While comprehensive, no detection system is 100% foolproof. Always exercise caution. User counts and detailed positive reviews are simulated as this data is not generally available from generic APIs.")
