import pandas as pd
import argparse
from datetime import datetime

# Severity mapping for prioritization
SEVERITY_MAP = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
SOURCE_WEIGHTS = {'AWS': 1.2, 'GitHub': 1.0}  # Adjust weightage for sources


def load_csv(file_path):
    """Load CSV file and handle errors."""
    try:
        df = pd.read_csv(file_path)
        df = df.drop_duplicates()
        return df
    except Exception as e:
        print(f"Error loading CSV file: {e}")
        return None


def process_data(df):
    """Process and clean vulnerability data."""
    print("Original columns:", df.columns.tolist())  # Debugging step
    
    df.columns = df.columns.str.strip()  # Remove any leading/trailing spaces
    df = df.rename(columns={
        'Identifier': 'CVE',  # Fix column name
        'CVSS': 'CVSS',
        'Package Name': 'Package',  # Fix column name
        'Fixed Version': 'Fixed_Version',  # Fix column name
        'First detected date': 'Discovery',  # Fix column name
        'Due date': 'Due_Date'  # Fix column name
    })
    
    if 'Due_Date' not in df.columns or 'Discovery' not in df.columns:
        print("Error: Required columns missing in input file. Check column names.")
        print("Available columns:", df.columns.tolist())
        return None
    
    df['Severity Score'] = df['Severity'].map(SEVERITY_MAP).fillna(1)
    df['Source Weight'] = df['Source'].map(SOURCE_WEIGHTS).fillna(1.0)
    
    # Convert dates
    df['Due_Date'] = pd.to_datetime(df['Due_Date'], errors='coerce', format='%m/%d/%Y')
    df['Discovery'] = pd.to_datetime(df['Discovery'], errors='coerce', format='%m/%d/%Y')
    
    # Days until due
    df['Days Until Due'] = (df['Due_Date'] - datetime.now()).dt.days.fillna(0)
    
    # Normalize Fixability
    df['Fix Available'] = df['Fixability'].apply(lambda x: 1 if x == 'Fixable' else 0)
    
    return df


def calculate_priority(df):
    """Calculate priority score based on multiple factors."""
    df['Priority Score'] = (
        df['CVSS'] * 3 + 
        df['Severity Score'] * 2 + 
        df['Fix Available'] * 2 +
        df['Source Weight'] * 1.5 -
        df['Days Until Due'] * 0.1
    )
    return df.sort_values(by='Priority Score', ascending=False)


def export_results(df, output_csv, output_json):
    """Export prioritized vulnerabilities to CSV and JSON."""
    df.to_csv(output_csv, index=False)
    df.to_json(output_json, orient='records', indent=4)
    print(f"Results saved to {output_csv} and {output_json}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability Prioritization Tool")
    parser.add_argument("input_file", nargs='?', default=None, help="Path to the CSV file containing vulnerabilities")
    parser.add_argument("--output_csv", default="prioritized_vulnerabilities.csv", help="CSV output filename")
    parser.add_argument("--output_json", default="prioritized_vulnerabilities.json", help="JSON output filename")
    
    args = parser.parse_args()
    
    if args.input_file is None:
        print("Error: Missing required argument 'input_file'. Please provide the CSV file path.")
    else:
        df = load_csv(args.input_file)
        if df is not None:
            df = process_data(df)
            if df is not None:
                df = calculate_priority(df)
                export_results(df, args.output_csv, args.output_json)
