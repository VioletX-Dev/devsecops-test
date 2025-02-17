# DevSecOps Technical Assessment

VulnTool: Vulnerability Prioritization Utility


# Overview
VulnTool is a command-line utility written in Go that ingests CSV data containing vulnerability
records, computes a normalized priority score (scaled from 0 to 10) for each vulnerability, and
exports the results in both CSV and JSON formats in miliseconds using goroutines concurrently. 

# Prerequisites

- **Go Language**: Version 1.18 or later. Download and installation instructions are available at:
  https://golang.org/dl.

- **CSV Input File**: VulnTool expects a CSV file with the following header fields:

      Unique ID, Asset name, Asset id, Organization/Account, Identifier, Source, CVSS,
      Title, Description, Package Name, Installed Version, Fixed Version, Remediation,
      Severity, Due date, First detected date, Fixability

  *Note*: Date fields ("Due date" and "First detected date") must be provided in the MM/DD/YY. 

# Build and Installation

1. **Clone the Repository**:
   git clone <repository_url>
2. **Navigate to the Project Directory**:
   cd vulntool
3. **Build the Executable**:
   go build -o vulntool

# Usage Instructions

Execute VulnTool with the following command-line flags:

    ./vulntool -input vuln_findings_export_ACMEINC20250205a-FULL.csv -output_csv prioritized_vulnerabilities.csv \
      -output_json prioritized_vulnerabilities.json -print=true

The available flags include:
  - `-input`: Path to the input CSV file.
  - `-output_csv`: Path to the output CSV file.
  - `-output_json`: Path to the output JSON file.
  - `-print`: Boolean flag to display the summary table on the terminal.
  - Severity weights: `-critical`, `-high`, `-medium`, `-low`
  - Source-specific weights: `-aws`, `-github`
  - Fix penalty: `-fix_bonus`

# Time Tracking:

Upon completion of processing, VulnTool logs the total processing time. For example:

    2025/02/17 12:58:11 Processing completed in 54.938791ms

This performance metric enables users to compare the efficiency of this Go implementation with alternative
approaches (e.g., Python-based solutions), which are typically slower due to interpreted runtime overhead.

# Code Architecture

### Data Model
The core entity is the `Vulnerability` struct. It maps directly to the CSV columns and includes computed fields:
  - **Basic Fields**: UniqueID, AssetName, AssetID, OrganizationAccount, Identifier, Source, CVSS, Title,
    Description, PackageName, InstalledVersion, FixedVersion, Remediation, Severity, DueDate, FirstDetectedDate, Fixability.
  - **Computed Fields**:
      - **PriorityScore**: Calculated based on a weighted combination of the CVSS score, severity, due date proximity,
        source of the vulnerability, and whether a fix is available.
      - **RecommendedActionTimeframe**: Suggests a remediation timeframe (Immediate, Urgent, or Scheduled) based on the due date.

### CSV Parsing and Date Conversion
- **CSV Parsing**:  
  The `readCSV` function opens the input CSV, builds a header-to-index mapping, and iterates through each record,
  converting rows into `Vulnerability` structs.
- **Date Conversion**:  
  The `convertMDYToISO` function transforms dates from the "M/D/YY" format into the ISO "YYYY-MM-DD" format,
  interpreting the two-digit year as 2000 + YY (e.g., "9/15/69" becomes "2069-09-15").

### Priority Scoring Algorithm
The `calculatePriorityScore` function computes a normalized score (0–10) by combining:
  - **CVSS Component**: CVSS score multiplied by a severity-specific weight.
  - **Time Component**: A bonus based on the number of days until the due date:
      - Bonus 3 if due within 7 days.
      - Bonus 2 if due within 30 days.
      - Bonus 1 otherwise.
  - **Source Component**: Additional bonus if the vulnerability originates from key sources (e.g., AWS or GitHub).
  - **Fix Component**: A penalty if a fix is available.
  
Weights are user-configurable via command-line flags, ensuring the final score is normalized on a 0–10 scale.

### Concurrency Model
VulnTool leverages Go’s native concurrency with a worker-pool pattern:
  - **Multithreading**:  
    The `processVulnerabilities` function spawns a number of goroutines equal to the number of CPU cores, each
    processing vulnerabilities concurrently.
  - **Goroutines & Channels**:  
    A channel-based pipeline feeds each vulnerability to a worker, which computes its priority score and recommended
    action timeframe. The results are aggregated from a results channel, ensuring efficient parallel processing even
    on large CSV files.

### Output Generation
VulnTool supports three output modes:
  - **CSV Export**:  
    The `writeCSV` function exports the processed vulnerabilities into a CSV file with an extended header.
  - **JSON Export**:  
    The `writeJSON` function outputs the data as well-formatted JSON.
  - **Terminal Display**:  
    The `printToTerminal` function renders a formatted summary table using Go’s `tabwriter` for quick review.

### Performance Metrics
The tool records the overall processing time and logs this value to standard output. This metric demonstrates the
efficiency of Go’s concurrent processing model, which typically outperforms equivalent Python implementations.


# Unit Testing

A comprehensive suite of unit tests is included to validate:
  - Date conversion via `convertMDYToISO`
  - Priority scoring via `calculatePriorityScore`
  - CSV parsing and output functions (`readCSV`, `writeCSV`, `writeJSON`)
  
To execute the tests, run:

    go test -v
