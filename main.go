package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)


type Vulnerability struct {
	UniqueID                   string    `json:"unique_id"`
	AssetName                  string    `json:"asset_name"`
	AssetID                    string    `json:"asset_id"`
	OrganizationAccount        string    `json:"organization_account"`
	Identifier                 string    `json:"identifier"`
	Source                     string    `json:"source"`
	CVSS                       float64   `json:"cvss"`
	Title                      string    `json:"title"`
	Description                string    `json:"description"`
	PackageName                string    `json:"package_name"`
	InstalledVersion           string    `json:"installed_version"`
	FixedVersion               string    `json:"fixed_version"`
	Remediation                string    `json:"remediation"`
	Severity                   string    `json:"severity"`
	DueDate                    time.Time `json:"due_date"`
	FirstDetectedDate          time.Time `json:"first_detected_date"`
	Fixability                 string    `json:"fixability"`
	PriorityScore              float64   `json:"priority_score"`
	RecommendedActionTimeframe string    `json:"recommended_action_timeframe"`
}

const theoreticalMax = 24.0

// convertMDYToISO converts a date from "M/D/YY" format to "YYYY-MM-DD".
// It always interprets the two-digit year as 2000+year.
func convertMDYToISO(dateStr string) (string, error) {
	parts := strings.Split(strings.TrimSpace(dateStr), "/")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid date format: %s", dateStr)
	}
	month, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", err
	}
	day, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", err
	}
	year, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", err
	}
	//always interpret the two-digit year as 2000 + year.
	year += 2000
	return fmt.Sprintf("%04d-%02d-%02d", year, month, day), nil
}


func readCSV(filename string) ([]Vulnerability, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	//allow variable number of fields.
	reader.FieldsPerRecord = -1

	var vulnerabilities []Vulnerability

	//read header row and build a header-to-index map.
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}
	headerMap := make(map[string]int)
	for i, field := range header {
		field = strings.TrimSpace(field)
		headerMap[field] = i
	}

	//read each record.
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("error reading record: %v", err)
			continue
		}
		if len(record) < len(header) {
			log.Printf("skipping malformed record: %v", record)
			continue
		}

		cvss, err := strconv.ParseFloat(strings.TrimSpace(record[headerMap["CVSS"]]), 64)
		if err != nil {
			log.Printf("error parsing CVSS: %v", err)
			continue
		}

		dueDateStr, err := convertMDYToISO(record[headerMap["Due date"]])
		if err != nil {
			log.Printf("error converting Due date: %v", err)
			continue
		}
		dueDate, err := time.Parse("2006-01-02", dueDateStr)
		if err != nil {
			log.Printf("error parsing Due date: %v", err)
			continue
		}

		firstDetectedStr, err := convertMDYToISO(record[headerMap["First detected date"]])
		if err != nil {
			log.Printf("error converting First detected date: %v", err)
			continue
		}
		firstDetected, err := time.Parse("2006-01-02", firstDetectedStr)
		if err != nil {
			log.Printf("error parsing First detected date: %v", err)
			continue
		}

		vuln := Vulnerability{
			UniqueID:            strings.TrimSpace(record[headerMap["Unique ID"]]),
			AssetName:           strings.TrimSpace(record[headerMap["Asset name"]]),
			AssetID:             strings.TrimSpace(record[headerMap["Asset id"]]),
			OrganizationAccount: strings.TrimSpace(record[headerMap["Organization/Account"]]),
			Identifier:          strings.TrimSpace(record[headerMap["Identifier"]]),
			Source:              strings.TrimSpace(record[headerMap["Source"]]),
			CVSS:                cvss,
			Title:               strings.TrimSpace(record[headerMap["Title"]]),
			Description:         strings.TrimSpace(record[headerMap["Description"]]),
			PackageName:         strings.TrimSpace(record[headerMap["Package Name"]]),
			InstalledVersion:    strings.TrimSpace(record[headerMap["Installed Version"]]),
			FixedVersion:        strings.TrimSpace(record[headerMap["Fixed Version"]]),
			Remediation:         strings.TrimSpace(record[headerMap["Remediation"]]),
			Severity:            strings.TrimSpace(record[headerMap["Severity"]]),
			DueDate:             dueDate,
			FirstDetectedDate:   firstDetected,
			Fixability:          strings.TrimSpace(record[headerMap["Fixability"]]),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	return vulnerabilities, nil
}

func calculatePriorityScore(v Vulnerability, weights map[string]float64) float64 {
	// Use the severity weight (default to 1.0 if not found).
	severityWeight := weights[v.Severity]
	if severityWeight == 0 {
		severityWeight = 1.0
	}
	cvssComponent := v.CVSS * severityWeight

	//calculate time factor based on days until due date.
	now := time.Now()
	daysLeft := v.DueDate.Sub(now).Hours() / 24
	var timeComponent float64
	if daysLeft <= 7 {
		timeComponent = 3
	} else if daysLeft <= 30 {
		timeComponent = 2
	} else {
		timeComponent = 1
	}

	//additional bonus for the source.
	var sourceComponent float64
	if v.Source == "AWS" {
		sourceComponent = weights["AWS"]
	} else if v.Source == "GitHub" {
		sourceComponent = weights["GitHub"]
	}

	//subtract penalty if a fix is available.
	var fixComponent float64
	if v.FixedVersion != "" {
		fixComponent = weights["FixBonus"]
	}

	rawScore := cvssComponent + timeComponent + sourceComponent - fixComponent
	normalizedScore := (rawScore / theoreticalMax) * 10.0
	return normalizedScore
}

func recommendedActionTimeframe(v Vulnerability) string {
	now := time.Now()
	daysLeft := v.DueDate.Sub(now).Hours() / 24
	if daysLeft <= 7 {
		return "Immediate"
	} else if daysLeft <= 30 {
		return "Urgent"
	}
	return "Scheduled"
}

func processVulnerabilities(vulns []Vulnerability, weights map[string]float64) []Vulnerability {
	var wg sync.WaitGroup
	vulnChan := make(chan Vulnerability, len(vulns))
	resultChan := make(chan Vulnerability, len(vulns))

	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for v := range vulnChan {
				v.PriorityScore = calculatePriorityScore(v, weights)
				v.RecommendedActionTimeframe = recommendedActionTimeframe(v)
				resultChan <- v
			}
		}()
	}

	for _, v := range vulns {
		vulnChan <- v
	}
	close(vulnChan)
	wg.Wait()
	close(resultChan)

	var processed []Vulnerability
	for v := range resultChan {
		processed = append(processed, v)
	}
	return processed
}

func writeCSV(filename string, vulns []Vulnerability) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Unique ID", "Asset name", "Asset id", "Organization/Account", "Identifier", "Source",
		"CVSS", "Title", "Description", "Package Name", "Installed Version", "Fixed Version",
		"Remediation", "Severity", "Due date", "First detected date", "Fixability", "PriorityScore", "RecommendedActionTimeframe",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}

	for _, v := range vulns {
		record := []string{
			v.UniqueID,
			v.AssetName,
			v.AssetID,
			v.OrganizationAccount,
			v.Identifier,
			v.Source,
			fmt.Sprintf("%.2f", v.CVSS),
			v.Title,
			v.Description,
			v.PackageName,
			v.InstalledVersion,
			v.FixedVersion,
			v.Remediation,
			v.Severity,
			v.DueDate.Format("2006-01-02"),
			v.FirstDetectedDate.Format("2006-01-02"),
			v.Fixability,
			fmt.Sprintf("%.2f", v.PriorityScore),
			v.RecommendedActionTimeframe,
		}
		if err := writer.Write(record); err != nil {
			log.Printf("failed to write record: %v", err)
		}
	}
	return nil
}

func writeJSON(filename string, vulns []Vulnerability) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(vulns); err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}
	return nil
}

func printToTerminal(vulns []Vulnerability) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Unique ID\tCVSS\tSeverity\tSource\tPriorityScore\tAction Timeframe")
	for _, v := range vulns {
		fmt.Fprintf(w, "%s\t%.2f\t%s\t%s\t%.2f\t%s\n",
			v.UniqueID, v.CVSS, v.Severity, v.Source, v.PriorityScore, v.RecommendedActionTimeframe)
	}
	w.Flush()
}

func main() {
	//record the start time.
	startTime := time.Now()

	inputCSV := flag.String("input", "vulnerabilities.csv", "Path to input CSV file")
	outputCSV := flag.String("output_csv", "prioritized_vulnerabilities.csv", "Path to output CSV file")
	outputJSON := flag.String("output_json", "prioritized_vulnerabilities.json", "Path to output JSON file")
	printOutput := flag.Bool("print", true, "Print output to terminal")

	criticalWeight := flag.Float64("critical", 2.0, "Weight for Critical severity")
	highWeight := flag.Float64("high", 1.5, "Weight for High severity")
	mediumWeight := flag.Float64("medium", 1.2, "Weight for Medium severity")
	lowWeight := flag.Float64("low", 1.0, "Weight for Low severity")
	awsWeight := flag.Float64("aws", 1.0, "Additional weight for AWS source")
	githubWeight := flag.Float64("github", 0.5, "Additional weight for GitHub source")
	fixBonus := flag.Float64("fix_bonus", 1.0, "Penalty weight if a fix is available")

	flag.Parse()

	weights := map[string]float64{
		"Critical": *criticalWeight,
		"High":     *highWeight,
		"Medium":   *mediumWeight,
		"Low":      *lowWeight,
		"AWS":      *awsWeight,
		"GitHub":   *githubWeight,
		"FixBonus": *fixBonus,
	}

	vulnerabilities, err := readCSV(*inputCSV)
	if err != nil {
		log.Fatalf("Error reading CSV: %v", err)
	}
	log.Printf("Read %d vulnerabilities", len(vulnerabilities))

	processed := processVulnerabilities(vulnerabilities, weights)

	sort.Slice(processed, func(i, j int) bool {
		return processed[i].PriorityScore > processed[j].PriorityScore
	})

	if err := writeCSV(*outputCSV, processed); err != nil {
		log.Fatalf("Error writing CSV: %v", err)
	}
	log.Printf("Output CSV written to %s", *outputCSV)

	if err := writeJSON(*outputJSON, processed); err != nil {
		log.Fatalf("Error writing JSON: %v", err)
	}
	log.Printf("Output JSON written to %s", *outputJSON)

	if *printOutput {
		fmt.Println("Prioritized Vulnerabilities:")
		printToTerminal(processed)
	}

	
	//calculate and print the total time taken.
	elapsed := time.Since(startTime)
	log.Printf("Processing completed in %v", elapsed)
}
