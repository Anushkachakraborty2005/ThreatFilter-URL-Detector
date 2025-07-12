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

## Model Workflow 🧠

Here's a high-level overview of how the ThreatFilter application processes a URL from submission to result display:

1.  **URL Submission & Initial API Query**
    * The user inputs a URL into the web interface.
    * Upon submission, the application encodes the URL and sends a request to the VirusTotal API.

2.  **VirusTotal Analysis & Classification**
    * VirusTotal processes the submitted URL, performing extensive scans through its array of security engines and threat intelligence databases.
    * Based on these scans, VirusTotal provides an assessment, classifying the URL as malicious, suspicious, harmless, or undetected.

3.  **Application Response Interpretation**
    * The application receives and interprets the comprehensive report from VirusTotal.
    * If the URL is flagged as **malicious** or **suspicious**, a clear warning message is displayed, indicating the number of security vendors that detected it and including simulated user reviews to caution the user.
    * If the URL is deemed **safe** (harmless or undetected), the application proceeds to gather more contextual information.

4.  **Website Content Extraction (for Safe URLs)**
    * For URLs confirmed to be safe by VirusTotal, the application attempts to make an HTTP GET request to the URL.
    * It then uses BeautifulSoup4 to parse the HTML content, extracting the page's title and meta description to provide a brief overview of the website.

5.  **Final Result Presentation**
    * All collected information—including the VirusTotal safety status, the scraped website description (if available), and simulated user engagement metrics—is cohesively presented to the user on the Streamlit dashboard, offering a complete picture of the URL's assessment.



---
