# Import necessary libraries
import pandas as pd
from datetime import datetime

# Load the CSV file
file_path = "vuln_findings_export_ACMEINC20250205a-FULL.csv"
df = pd.read_csv(file_path)

# Convert date fields to datetime format
date_columns = ["Due date", "First detected date"]
for col in date_columns:
    df[col] = pd.to_datetime(df[col], errors="coerce")

# Standardize severity levels (convert to lowercase for consistency)
df["Severity"] = df["Severity"].str.lower()

# Define severity mapping for scoring
severity_mapping = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2
}

# Map severity to numerical values
df["Severity Score"] = df["Severity"].map(severity_mapping).fillna(0)

# Compute days until due date
today = datetime.today()
df["Days Until Due"] = (df["Due date"] - today).dt.days

# Identify fix availability (binary: 1 if fixable, 0 if not)
df["Fixable"] = df["Fixability"].apply(lambda x: 1 if str(x).lower() == "fixable" else 0)

# Define source weighting (higher reliability = higher score)
source_weighting = {
    "nvd": 1.5,
    "github": 1.2,
    "other": 1.0
}
df["Source Weight"] = df["Source"].str.lower().map(source_weighting).fillna(1.0)

# Define weights for prioritization factors
weights = {
    "cvss": 0.4,  # CVSS score is a major factor
    "severity": 0.3,  # Severity level contributes significantly
    "due_date": 0.2,  # Time urgency matters
    "fixability": 0.1,  # If a fix is available, it should be prioritized
    "source": 0.1  # Source reliability is a minor factor
}

# Normalize CVSS and Severity Scores to a 0-1 scale
normalized_cvss = df["CVSS"] / 10
normalized_severity = df["Severity Score"] / 10

# Calculate urgency score based on due date (earlier due dates get higher scores)
urgency_score = 1 / (1 + df["Days Until Due"].clip(lower=1))

# Assign extra weight if a fix is available
fixability_score = df["Fixable"]

# Adjust priority based on source reliability
source_reliability = df["Source Weight"]

# Compute the final priority score using weighted factors
df["Priority Score"] = (
    (normalized_cvss * weights["cvss"]) +
    (normalized_severity * weights["severity"]) +
    (urgency_score * weights["due_date"]) +
    (fixability_score * weights["fixability"]) +
    (source_reliability * weights["source"])
)

# Sort vulnerabilities by priority score (descending order)
df_sorted = df.sort_values(by="Priority Score", ascending=False)

# Define file paths for output
csv_output_path = "prioritized_vulnerabilities.csv"
json_output_path = "prioritized_vulnerabilities.json"

# Save to CSV
df_sorted.to_csv(csv_output_path, index=False)

# Save to JSON
df_sorted.to_json(json_output_path, orient="records", indent=4)

