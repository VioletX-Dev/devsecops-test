package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConvertMDYToISO(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"9/15/69", "2069-09-15"}, // per our requirement, 69 becomes 2069.
		{"7/4/24", "2024-07-04"},
		{"12/31/99", "2099-12-31"},
	}

	for _, tt := range tests {
		got, err := convertMDYToISO(tt.input)
		if err != nil {
			t.Errorf("convertMDYToISO(%q) returned error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("convertMDYToISO(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCalculatePriorityScore(t *testing.T) {
	now := time.Now()
	vuln := Vulnerability{
		CVSS:         9.0,
		Severity:     "Critical",
		DueDate:      now.Add(5 * 24 * time.Hour), // within 7 days: bonus 3
		Source:       "AWS",
		FixedVersion: "",
	}
	weights := map[string]float64{
		"Critical": 2.0,
		"High":     1.5,
		"Medium":   1.2,
		"Low":      1.0,
		"AWS":      1.0,
		"GitHub":   0.5,
		"FixBonus": 1.0,
	}
	// Raw score would be (9.0 * 2.0) + 3 (time bonus) + 1.0 (AWS bonus) = 22.
	// Normalized score = (22 / 24) * 10 ≈ 9.17.
	expected := 9.17
	score := calculatePriorityScore(vuln, weights)
	const tolerance = 0.01
	if abs(score-expected) > tolerance {
		t.Errorf("Expected normalized score ≈ %v, got %v", expected, score)
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func TestRecommendedActionTimeframe(t *testing.T) {
	now := time.Now()
	vulnImmediate := Vulnerability{DueDate: now.Add(3 * 24 * time.Hour)}
	vulnUrgent := Vulnerability{DueDate: now.Add(10 * 24 * time.Hour)}
	vulnScheduled := Vulnerability{DueDate: now.Add(40 * 24 * time.Hour)}

	if tf := recommendedActionTimeframe(vulnImmediate); tf != "Immediate" {
		t.Errorf("Expected Immediate, got %s", tf)
	}
	if tf := recommendedActionTimeframe(vulnUrgent); tf != "Urgent" {
		t.Errorf("Expected Urgent, got %s", tf)
	}
	if tf := recommendedActionTimeframe(vulnScheduled); tf != "Scheduled" {
		t.Errorf("Expected Scheduled, got %s", tf)
	}
}

func createTempCSV(content string) (string, error) {
	tmpfile, err := os.CreateTemp("", "test_vuln_*.csv")
	if err != nil {
		return "", err
	}
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		tmpfile.Close()
		return "", err
	}
	tmpfile.Close()
	return tmpfile.Name(), nil
}

func TestReadCSV(t *testing.T) {
	csvContent := `Unique ID,Asset name,Asset id,Organization/Account,Identifier,Source,CVSS,Title,Description,Package Name,Installed Version,Fixed Version,Remediation,Severity,Due date,First detected date,Fixability
CVE-0001,TestAsset,12345,ACMEINC,ID-001,AWS,7.5,Test Title,Test vulnerability,TestPackage,,,"",High,2/10/25,2/20/25,Fixable
CVE-0002,AnotherAsset,54321,ACMEINC,ID-002,GitHub,5.0,Another Title,Another vulnerability,AnotherPackage,1.0.0,1.2.3,Remediate,Medium,2/05/25,3/01/25,Not Fixable
`
	filename, err := createTempCSV(csvContent)
	if err != nil {
		t.Fatalf("Error creating temp CSV: %v", err)
	}
	defer os.Remove(filename)

	vulns, err := readCSV(filename)
	if err != nil {
		t.Fatalf("readCSV returned error: %v", err)
	}
	if len(vulns) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(vulns))
	}
	if vulns[0].UniqueID != "CVE-0001" {
		t.Errorf("Expected UniqueID 'CVE-0001', got %s", vulns[0].UniqueID)
	}
	if vulns[1].FixedVersion != "1.2.3" {
		t.Errorf("Expected FixedVersion '1.2.3', got %s", vulns[1].FixedVersion)
	}
}

func TestWriteCSV(t *testing.T) {
	now := time.Now()
	vulns := []Vulnerability{
		{
			UniqueID:                "CVE-TEST-1",
			AssetName:               "Asset1",
			AssetID:                 "ID1",
			OrganizationAccount:     "ACMEINC",
			Identifier:              "ID-TEST",
			Source:                  "AWS",
			CVSS:                    6.5,
			Title:                   "Title1",
			Description:             "Test vulnerability 1",
			PackageName:             "TestPkg1",
			InstalledVersion:        "1.0",
			FixedVersion:            "",
			Remediation:             "Remediate",
			Severity:                "Medium",
			DueDate:                 now,
			FirstDetectedDate:       now.Add(-24 * time.Hour),
			Fixability:              "Fixable",
			PriorityScore:           10.0,
			RecommendedActionTimeframe: "Urgent",
		},
	}
	tmpfile, err := os.CreateTemp("", "output_*.csv")
	if err != nil {
		t.Fatalf("Error creating temp CSV file: %v", err)
	}
	filename := tmpfile.Name()
	tmpfile.Close()
	defer os.Remove(filename)

	if err := writeCSV(filename, vulns); err != nil {
		t.Fatalf("writeCSV returned error: %v", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Error reading written CSV file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "CVE-TEST-1") {
		t.Errorf("CSV content does not contain expected CVE-TEST-1")
	}

	reader := csv.NewReader(strings.NewReader(content))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Error parsing written CSV: %v", err)
	}
	if len(records) < 2 {
		t.Errorf("Expected header and at least one data record, got %d records", len(records))
	}
}


func TestWriteJSON(t *testing.T) {
	now := time.Now()
	vulns := []Vulnerability{
		{
			UniqueID:                "CVE-TEST-2",
			AssetName:               "Asset2",
			AssetID:                 "ID2",
			OrganizationAccount:     "ACMEINC",
			Identifier:              "ID-TEST-2",
			Source:                  "GitHub",
			CVSS:                    8.0,
			Title:                   "Title2",
			Description:             "Test vulnerability 2",
			PackageName:             "TestPkg2",
			InstalledVersion:        "2.0",
			FixedVersion:            "2.3.4",
			Remediation:             "Update",
			Severity:                "Critical",
			DueDate:                 now,
			FirstDetectedDate:       now.Add(-48 * time.Hour),
			Fixability:              "Fixable",
			PriorityScore:           15.0,
			RecommendedActionTimeframe: "Immediate",
		},
	}
	tmpfile, err := os.CreateTemp("", "output_*.json")
	if err != nil {
		t.Fatalf("Error creating temp JSON file: %v", err)
	}
	filename := tmpfile.Name()
	tmpfile.Close()
	defer os.Remove(filename)

	if err := writeJSON(filename, vulns); err != nil {
		t.Fatalf("writeJSON returned error: %v", err)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Error reading written JSON file: %v", err)
	}
	var out []Vulnerability
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Error unmarshalling JSON: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("Expected 1 vulnerability in JSON, got %d", len(out))
	}
	if out[0].UniqueID != "CVE-TEST-2" {
		t.Errorf("Expected UniqueID 'CVE-TEST-2', got %s", out[0].UniqueID)
	}
}
