# ThreatFilter - Spam URL Detection

## Live Preview

Experience the app live: [Live Preview](https://threatfilter-url-detector-ccqbgqkascrccmkh7ksssc.streamlit.app/)

## Project Aim

The primary aim of the **ThreatFilter - Spam URL Detection** project is to provide a real-time, user-friendly web application to help users identify potentially malicious or spam URLs. By leveraging the VirusTotal API, the application scans submitted URLs against a comprehensive database of security vendors, providing immediate feedback on the URL's safety status. For safe URLs, it attempts to provide a brief, relevant description of the website content through web scraping, enhancing user confidence. The tool is designed to be an accessible first line of defense against phishing, malware, and other web-based threats.

## Tech Stack

This project is built using the following technologies:

* **Python**: The core programming language for the application logic.
* **Streamlit**: Used for building the interactive and responsive web user interface.
* **Requests**: A robust HTTP library for making API calls to VirusTotal and fetching web page content.
* **BeautifulSoup4 (bs4)**: A Python library for parsing HTML and XML documents, used for web scraping page descriptions.
* **python-dotenv**: For securely loading environment variables (like API keys) from a `.env` file during local development.
* **VirusTotal API**: The primary service used for checking the safety and reputation of URLs.


## Screenshots

Here are some screenshots illustrating the application's interface and functionality:

### 🖼️ Main Interface 

This image displays the overall layout of the ThreatFilter application, including the sidebar with information and the main area for URL input.

![ThreatFilter Main Interface](https://github.com/user-attachments/assets/24b4e8b7-35f7-446b-8575-730166587f38)




### 2.Safe URL Test 🔍

This screenshot shows the result when a benign (safe) URL is scanned, displaying confirmation of its safety and providing website information.

!![Safe URL Test](https://github.com/user-attachments/assets/161ec9af-c7ee-4e65-b2dd-9559b0e47cc6)



### 3. Malicious URL Test ⚠

This image demonstrates how the application warns users about potentially malicious URLs, indicating the number of detections and providing simulated user reviews.

![Malicous URL Test](https://github.com/user-attachments/assets/097f1601-b21a-4fea-ba41-5d94f4c147fd)

This application offers the following key features:

* ⚡ **Real-time URL Threat Analysis**: Quickly scans URLs using the VirusTotal API to determine their safety status.
* 📄 **Automatic Website Content Description**: For safe URLs, attempts to fetch and display a brief description of the website content through web scraping.
* 📊 **Simulated User Engagement Metrics**: Provides simulated user reviews and estimated user counts to give a holistic (though not real-time) view of a URL's perceived reputation.

## Model Workflow 🧠

Here's a concise overview of how the ThreatFilter application processes a URL:

1.  **URL Submission & API Query**
    * User input is captured via the Streamlit frontend.
    * The URL is Base64 encoded for the VirusTotal API request.

2.  **VirusTotal Analysis & Classification**
    * An external API call is made to VirusTotal for comprehensive threat intelligence.
    * The application retrieves `last_analysis_stats` (malicious, suspicious, harmless, undetected counts) from the API response.

3.  **Application Response Interpretation**
    * Python logic parses the JSON report received from VirusTotal.
    * Streamlit's UI components are conditionally rendered based on `malicious_count` and `suspicious_count`.

4.  **Website Content Extraction (for Safe URLs)**
    * An HTTP GET request is performed on the URL using the `requests` library.
    * HTML content is parsed with BeautifulSoup4 to extract `title` and `meta description` tags.

5.  **Final Result Presentation**
    * Consolidated analysis results are displayed using various Streamlit UI components (e.g., `st.success`, `st.error`).
    * Simulated user reviews and metrics are presented for enhanced contextual feedback.
  ---
## Model Effectiveness ✨

The effectiveness of the ThreatFilter application is assessed through its robust integration and reliable performance:

* **API-Driven Threat Detection**: The primary effectiveness in identifying malicious or suspicious URLs directly stems from the comprehensive and real-time threat intelligence provided by the VirusTotal API.
* **Contextual Data Enrichment**: The application's ability to accurately scrape and present relevant website descriptions for safe URLs enhances its utility, providing users with immediate context beyond just security status.
* **User Interaction & Reliability**: The overall effectiveness is also measured by the Streamlit application's responsiveness, ease of use, and consistent performance in processing user queries and delivering clear results.

## 📁 Project Structure
ThreatFilter-URL-Detector/
├── .streamlit/             # Streamlit specific configuration files (auto-generated)
├── venv/                   # Python virtual environment (ignored by Git)
├── screenshots/            # Directory to store project screenshots
│   ├── image_25f555.png    # Screenshot of Main Interface
│   ├── image_25f0de.png    # Screenshot of Safe URL Test
│   └── image_25f519.png    # Screenshot of Malicious URL Test
├── app.py                  # Main Streamlit application file
├── .env                    # Environment variables for API keys (ignored by Git)
├── .gitignore              # Specifies intentionally untracked files to ignore
└── requirements.txt        # List of Python dependencies



---
