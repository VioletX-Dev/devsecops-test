# Vulnerability Prioritization Tool

## Overview
This tool processes vulnerability data from a CSV file, prioritizing vulnerabilities based on CVSS score, severity, fix availability, source weight, and due date. The output is a sorted list of vulnerabilities with assigned priority scores.

## Features
- Reads and processes a CSV file containing vulnerability data.
- Implements a scoring system to prioritize vulnerabilities.
- Exports the prioritized list to CSV and JSON formats.
- Includes unit tests for validation.

## Installation
### **Prerequisites**
Ensure you have Python installed (>=3.7).

### **Install Dependencies**
```sh
pip install -r requirements.txt
```

## Usage
### **Running the Tool**
```sh
python main.py <input_file.csv>
```

Example:
```sh
python main.py vuln_findings.csv --output_csv prioritized.csv --output_json prioritized.json
```

### **Running Unit Tests**
To verify the implementation, run:
```sh
python -m unittest test_vulnerability_prioritization.py
```

## Algorithm
The prioritization formula is:
```
Priority Score = (CVSS * 3) + (Severity Score * 2) + (Fix Available * 2) + (Source Weight * 1.5) - (Days Until Due * 0.1)
```
- **Higher scores indicate more critical vulnerabilities.**
- **Severity levels:** Critical (4), High (3), Medium (2), Low (1).
- **Fixable vulnerabilities get an additional boost in score.**

For more details, see [Algorithm Approach](algorithm_approach.md).

## File Structure
```
.
├── main.py                   # Main script for prioritization
├── test_vulnerability_prioritization.py  # Unit tests
├── requirements.txt           # Required dependencies
├── README.md                 # Documentation
├── Algorithm Approach.docx      # Algorithm explanation
```
