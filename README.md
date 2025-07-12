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
  # ThreatFilter - Spam URL Detection

## Screenshots

Here are some screenshots illustrating the application's interface and functionality:

### 1. 🖼️ Main Interface

This image displays the overall layout of the ThreatFilter application, including the sidebar with information and the main area for URL input.

![Malicious URL Test](https://github.com/user-attachments/assets/d30bbbe7-8914-4edd-96a7-02f82761bf48)


### 2.Safe URL Test 🔍

This screenshot shows the result when a benign (safe) URL is scanned, displaying confirmation of its safety and providing website information.

![Safe URL Test](https://github.com/user-attachments/assets/718e8bbc-f755-410b-ab66-8a92d7e4eead)


### 3. Malicious URL Test ⚠

This image demonstrates how the application warns users about potentially malicious URLs, indicating the number of detections and providing simulated user reviews.

![ThreatFilter Main Interface](https://github.com/user-attachments/assets/eeb8dfc3-59c0-4886-9e96-d3e9bbfb1374)


This application offers the following key features:

* ⚡ **Real-time URL Threat Analysis**: Quickly scans URLs using the VirusTotal API to determine their safety status.
* 📄 **Automatic Website Content Description**: For safe URLs, attempts to fetch and display a brief description of the website content through web scraping.
* 📊 **Simulated User Engagement Metrics**: Provides simulated user reviews and estimated user counts to give a holistic (though not real-time) view of a URL's perceived reputation.

## Model Workflow

Here's a high-level overview of how the ThreatFilter application processes a URL:

1.  **User Input**: The user enters a URL into the provided input field and clicks the "Check URL" button.
2.  **VirusTotal API Query**: The application sends the submitted URL to the VirusTotal API for comprehensive threat analysis. The URL is first Base64-encoded as required by the API.
3.  **Threat Analysis**: VirusTotal scans the URL using numerous security engines and databases, returning a detailed report on its malicious, suspicious, harmless, or undetected status.
4.  **Status Interpretation**: The application interprets VirusTotal's response:
    * If the URL is flagged as **malicious**, a prominent danger warning is displayed along with the count of detecting vendors and simulated negative user reviews.
    * If the URL is flagged as **suspicious**, a warning is shown with a concise message and simulated cautious user reviews.
    * If the URL is **safe** (no malicious or suspicious flags), a success message is displayed.
    * If the URL is **not found** in VirusTotal's database, an informational message is provided, suggesting it might be a new or unscanned URL.
    * Any **API errors** (e.g., rate limits, invalid key) are explicitly reported.
5.  **Website Content Scraping (for Safe URLs)**: If the URL is determined to be safe, the application then performs a separate web scraping operation using `Requests` and `BeautifulSoup4` to fetch the website's title and meta description, providing a one-line summary of its content.
6.  **Display Results**: All relevant information, including the safety status, content description (if available), and simulated user metrics, is presented clearly in the Streamlit interface.


---
