import streamlit as st
import requests
import base64
import os
from bs4 import BeautifulSoup 
import urllib3 

# Suppress InsecureRequestWarning when verify=False is used (for demonstration only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(layout="centered", page_title="ThreatFilter - Spam URL Detection", initial_sidebar_state="expanded")

# --- VirusTotal API Key (HARDCODED FOR IMMEDIATE DEMONSTRATION - INSECURE!) ---
# Replace this with your actual key.
# For production, NEVER hardcode your key like this. Use environment variables instead.
VIRUSTOTAL_API_KEY = "2899e8906c1aa55bcb3286030ecb5e632ef96556c0713cca527dcafe8137c29f"

# --- Web Scraping Function to get Page Description ---
def fetch_page_description(url):
    """
    Fetches the title and meta description from a given URL using html.parser.
    Returns a concise string description.
    """
    try:
        # Use a user-agent to mimic a browser, as some sites block default Python requests
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        
        # Add a timeout to prevent hanging indefinitely
        response = requests.get(url, headers=headers, timeout=5, verify=False) 
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        
        soup = BeautifulSoup(response.text, 'html.parser') # Parse the HTML content
        
        title = soup.find('title')
        description_meta = soup.find('meta', attrs={'name': 'description'}) or \
                           soup.find('meta', attrs={'property': 'og:description'})
        
        page_title = title.get_text().strip() if title else "No Title Found"
        page_description = description_meta.get('content', '').strip() if description_meta else ""

        if page_description:
            return f"{page_title}: {page_description}"
        elif page_title and page_title != "No Title Found":
            return page_title # Just use the title if no description
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
    Returns (status, message, details_or_reviews)
    Status can be: 'malicious', 'suspicious', 'safe', 'not_found', 'api_error'
    """
    if not url:
        return 'error', "No URL provided.", []

    if not VIRUSTOTAL_API_KEY:
        return 'error', "VirusTotal API Key is missing. Please configure it.", []

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json"
    }

    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(report_url, headers=headers)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if "data" in data:
            attributes = data["data"].get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})

            malicious_count = last_analysis_stats.get("malicious", 0)
            suspicious_count = last_analysis_stats.get("suspicious", 0)
            
            # Prepare detailed reviews from vendors
            vendor_details = []
            last_analysis_results = attributes.get("last_analysis_results", {})
            for engine, result in last_analysis_results.items():
                category = result.get("category")
                if category in ["malicious", "suspicious", "undetected", "harmless"]:
                    vendor_details.append(f"**{engine}**: {result.get('result', 'N/A')} (Category: {category})")
            
            if malicious_count > 0:
                message = f"Detected by {malicious_count} security vendors as malicious. Proceed with extreme caution."
                return 'malicious', message, vendor_details
            
            elif suspicious_count > 0:
                message = f"Detected by {suspicious_count} security vendors as suspicious. Review this URL carefully."
                return 'suspicious', message, vendor_details
            else:
                harmless_count = last_analysis_stats.get("harmless", 0)
                undetected_count = last_analysis_stats.get("undetected", 0)
                message = f"VirusTotal scan shows no malicious or suspicious flags (Harmless: {harmless_count}, Undetected: {undetected_count})."
                return 'safe', message, vendor_details # Return "safe" with vendor details
        else:
            return 'not_found', "URL not found in VirusTotal's database or no recent analysis available. It might be a very new URL or not widely scanned.", []

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            return 'not_found', "URL not found in VirusTotal's database. It might be a very new URL.", []
        elif response.status_code == 400:
            return 'api_error', "Bad request to VirusTotal API. Check URL format. (HTTP 400).", []
        elif response.status_code == 429:
            return 'api_error', "VirusTotal API rate limit exceeded. Please wait a moment and try again. (HTTP 429).", []
        elif response.status_code == 401:
            return 'api_error', "VirusTotal API Key invalid or unauthorized. Please check your API key. (HTTP 401).", []
        else:
            return 'api_error', f"HTTP error occurred: {http_err} - Status: {response.status_code}. Please try again later.", []
    except requests.exceptions.ConnectionError as conn_err:
        return 'api_error', f"Network error occurred: {conn_err}. Could not connect to VirusTotal. Check your internet connection.", []
    except Exception as err:
        return 'api_error', f"An unexpected error occurred: {err}. Please try again.", []


# --- Sidebar Content ---
with st.sidebar:
    # Main Sidebar Title
    st.markdown("<h2 style='color: #E0E0E0;'>🌐 ThreatFilter Info</h2>", unsafe_allow_html=True) 
    st.markdown("---")

    # App Information Section
    st.markdown("<h3 style='color: #FF6347;'>🛡️ App Information</h3>", unsafe_allow_html=True) 
    st.write("This app helps you detect potentially spam or malicious URLs using the VirusTotal API.")
    st.write("It also attempts to provide a brief description of safe websites through web scraping.")
    st.markdown("---")

    # Features Section
    st.markdown("<h3 style='color: #6495ED;'>🔍 Features</h3>", unsafe_allow_html=True) 
    st.markdown("- Real-time URL threat analysis")
    st.markdown("- Detailed vendor detections for malicious/suspicious URLs")
    st.markdown("- Automatic website content description (for safe URLs)")
    st.markdown("- Simulated user engagement metrics (reviews, estimated users)")
    st.markdown("---")

    # Tech Stack Section
    st.markdown("<h3 style='color: #90EE90;'>💻 Tech Stack</h3>", unsafe_allow_html=True) 
    st.markdown("- Python")
    st.markdown("- Streamlit")
    st.markdown("- Requests (HTTP client)")
    st.markdown("- BeautifulSoup4 (HTML parsing)")
    st.markdown("- VirusTotal API")
    st.markdown("---")
    
    # Developed by Section (Updated for LinkedIn Link)
    st.markdown("<h3 style='color: #FFD700;'>👨‍💻 Developed by:</h3>", unsafe_allow_html=True) 
    # Replace 'YOUR_LINKEDIN_PROFILE_URL' with your actual LinkedIn profile URL
    # Replace 'Your Name/Alias Here' with the text you want to display
    st.markdown("[Anushka Chakraborty](https://www.linkedin.com/in/anushka-chakraborty-006881311/L)", unsafe_allow_html=True) 


# --- Main Content Area ---
# Changed main header to use markdown for color
st.markdown("<h1 style='text-align: center; color: #FF6347;'>🛡️ ThreatFilter <span style='color: #6495ED;'>— Spam URL Detection</span></h1>", unsafe_allow_html=True)
st.markdown("---")
st.markdown("<h3 style='color: #ADD8E6;'>🔗 Enter a URL below to check if it's safe and get analysis from VirusTotal.</h3>", unsafe_allow_html=True)

url_input = st.text_input("Enter URL here", "https://www.example.com", help="e.g., https://www.google.com, https://docs.streamlit.io") 

if st.button("🔍 Check URL", use_container_width=True): 
    if url_input:
        with st.spinner("⏳ Checking URL... This may take a moment."): 
            status, message, details = check_url_virustotal(url_input)

            if status == 'malicious':
                st.error("🚨 DANGER: This URL is potentially malicious!")
                st.warning(message)
                if details:
                    st.subheader("⚠️ Vendor Detections:")
                    for detail in details:
                        st.markdown(f"- {detail}")
                else:
                    st.info("No specific vendor details available, but the URL is flagged as malicious.")
            
            elif status == 'suspicious':
                st.warning("⚠️ This URL is flagged as suspicious!")
                st.info(message)
                if details:
                    st.subheader("❓ Vendor Suspicions:")
                    for detail in details:
                        st.markdown(f"- {detail}")

            elif status == 'safe':
                st.success("✅ This URL appears safe based on VirusTotal analysis.")
                st.info(message)
                
                st.subheader("🌐 Website Information:") 
                
                # --- Fetch actual description via scraping ---
                with st.spinner("🕸️ Fetching page description..."): 
                    page_description = fetch_page_description(url_input)
                    st.write(page_description)

                # --- SIMULATED USER COUNTS / REVIEWS (as these cannot be scraped generally) ---
                st.markdown("<h4 style='color: #90EE90;'>👥 Estimated Users: Millions of users daily (Simulated)</h4>", unsafe_allow_html=True) 
                
                st.markdown("<h4 style='color: #FFD700;'>⭐ Good Reviews (Simulated):</h4>", unsafe_allow_html=True) 
                st.markdown("- User A: 'Clean and reliable website. Highly recommended!'")
                st.markdown("- User B: 'Fast loading and great user experience.'")
                st.markdown("- User C: 'A trustworthy source for information.'")
                st.markdown("*(Note: User counts and reviews are simulated, as this data is generally not available via generic web scraping or threat APIs.)*")
                # --- END SIMULATED DATA ---
                
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