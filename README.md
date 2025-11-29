Automated Reconnaissance Tool – Python
This project is a GUI-based Automated Reconnaissance Tool developed using Python for performing information-gathering and OSINT on web targets. The tool collects critical security details such as DNS information, WHOIS data, HTTP headers, SSL certificate details, server technologies, metadata, admin panel discovery, and screenshots — all in one place.
It is designed to assist cybersecurity learners, penetration testers, and analysts in performing fast, efficient, and automated reconnaissance before any security assessment.

Project Overview
The Automated Recon Tool is capable of:
•	Resolving domain information
•	Retrieving geolocation details of the IP
•	Performing WHOIS lookup
•	Extracting DNS records (A, MX, TXT, NS)
•	Fetching HTTP response headers
•	Checking SSL certificate validity
•	Identifying hidden pages like admin panels
•	Scraping metadata from HTML
•	Detecting tech stack using BuiltWith
•	Capturing a live screenshot of the target
•	Generating a complete text-based recon report
The application uses Tkinter for the GUI, Selenium for screenshots, and several popular Python libraries for OSINT.

Purpose of the Project
This project was developed as part of a Cyber Security Internship to demonstrate the ability to automate reconnaissance tasks that are usually performed manually during web penetration testing.
It simplifies the recon phase by providing a single tool that gathers all essential information quickly and presents it in a structured output.

Technologies Used
•	Python
•	Tkinter (GUI)
•	Requests
•	DNS Resolver
•	Selenium WebDriver
•	BuiltWith API
•	BeautifulSoup (HTML Parsing)
•	WHOIS
•	PIL (Image Processing)
•	FPDF (Report Generation)
Features
•	Easy-to-use graphical interface
•	Multi-threaded scanning (no GUI freeze)
•	Dark-themed output console
•	Automatic screenshot capturing
•	Auto-report generation
•	Organized output folders
•	Project info viewer (HTML-based)
•	Fast, portable, and highly useful for OSINT tasks
