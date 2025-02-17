Vulnerability Prioritization System

Setup Instructions
Prerequisites:
Python 3.x
pip (Python package manager)

Installation
Clone or download the repository.
Navigate to the project directory.
Install the required dependencies:
pip install -r requirements.txt

Running the Script
Place the CSV file (vuln_findings_export.csv) in the project directory.

Run the script:
python prioritize_vulnerabilities.py

The output will be generated as:
prioritized_vulnerabilities.csv
prioritized_vulnerabilities.json

Usage Example
python prioritize_vulnerabilities.py

Expected output: A sorted list of vulnerabilities in CSV and JSON formats, ranked by priority.

Prioritization Algorithm
The priority score is calculated based on the following factors:
CVSS Score (40%) - Higher CVSS scores indicate more critical vulnerabilities.
Severity Level (30%) - Severity categories (Critical, High, Medium, Low) mapped to numerical values.
Time Urgency (20%) - The closer the due date, the higher the priority.
Fix Availability (10%) - If a fix is available, the priority increases.
Source Reliability (10%) - More trusted sources (e.g., NVD) are weighted higher.

Each of these factors contributes a weighted value to the final priority score, ensuring that vulnerabilities with a combination of high severity, urgent due dates, and available fixes are ranked the highest.

Assumptions:
Missing or malformed data is ignored where possible.
Due dates are assumed to be in a standard format (YYYY-MM-DD).
Unknown severity levels default to the lowest score.
Source reliability is predefined (NVD > GitHub > Other).

Output:
The script generates:
CSV File: prioritized_vulnerabilities.csv (for easy viewing)
JSON File: prioritized_vulnerabilities.json (for API usage or further processing)

Notes
This tool helps security teams focus on the most pressing vulnerabilities based on multiple risk factors. Adjust weights if needed to suit specific requirements.

