# infoSecurityproject
This project is an automation tool for detecting XSS (Cross-Site Scripting) vulnerabilities in web applications.
It automatically scans the target website, tests input fields and URL parameters for potential XSS payload reflections, and generates a detailed report.

How to use?
1. Run the make_report.py file
2. Enter a URL for the website you wish to scan.
3. The tool will:
   * scrape the website and extract reachable pages and input points.
   * Test each page for Reflected XSS and Stored XSS vulnerabilities.
   * Generate a report in the folder 'reports' titled with a timestamp of when the report was made.
       a report includes: A list of scanned pages and parameters, the payloads used to check the vulnerable place,
                           encoding type (if used) and if it found an XSS vulnerability and if it verified it and suggestion to fix. 
     
     
         
