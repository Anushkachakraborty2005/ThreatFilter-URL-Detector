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

(![Malicious URL Test](https://github.com/user-attachments/assets/d30bbbe7-8914-4edd-96a7-02f82761bf48)


### 2.Safe URL Test 🔍

This screenshot shows the result when a benign (safe) URL is scanned, displaying confirmation of its safety and providing website information.

(![Safe URL Test](https://github.com/user-attachments/assets/718e8bbc-f755-410b-ab66-8a92d7e4eead)


### 3. Malicious URL Test ⚠

This image demonstrates how the application warns users about potentially malicious URLs, indicating the number of detections and providing simulated user reviews.

![ThreatFilter Main Interface](https://github.com/user-attachments/assets/eeb8dfc3-59c0-4886-9e96-d3e9bbfb1374)


---
