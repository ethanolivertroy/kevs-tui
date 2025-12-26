package grc

// NIST80053Controls contains vulnerability-relevant NIST 800-53 Rev 5 controls
var NIST80053Controls = map[string]SecurityControl{
	"SI-2": {
		ID:          "SI-2",
		Family:      "System and Information Integrity",
		Name:        "Flaw Remediation",
		Description: "Identify, report, and correct system flaws. Install security-relevant software updates within organization-defined time period.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"RA-5": {
		ID:          "RA-5",
		Family:      "Risk Assessment",
		Name:        "Vulnerability Monitoring and Scanning",
		Description: "Monitor and scan for vulnerabilities in the system and hosted applications. Employ vulnerability monitoring tools using CVE, CWE, and NVD databases.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"CM-6": {
		ID:          "CM-6",
		Family:      "Configuration Management",
		Name:        "Configuration Settings",
		Description: "Establish and document configuration settings for system components using security configuration checklists.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"CM-8": {
		ID:          "CM-8",
		Family:      "Configuration Management",
		Name:        "System Component Inventory",
		Description: "Develop and document an inventory of system components that accurately reflects the system and is consistent with the authorization boundary.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"CA-7": {
		ID:          "CA-7",
		Family:      "Assessment, Authorization, and Monitoring",
		Name:        "Continuous Monitoring",
		Description: "Develop a continuous monitoring strategy and implement a continuous monitoring program that includes ongoing security and privacy control assessments.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"IR-4": {
		ID:          "IR-4",
		Family:      "Incident Response",
		Name:        "Incident Handling",
		Description: "Implement an incident handling capability for incidents that includes preparation, detection, analysis, containment, eradication, and recovery.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"IR-6": {
		ID:          "IR-6",
		Family:      "Incident Response",
		Name:        "Incident Reporting",
		Description: "Require personnel to report suspected incidents to the organizational incident response capability within organization-defined time period.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"SC-7": {
		ID:          "SC-7",
		Family:      "System and Communications Protection",
		Name:        "Boundary Protection",
		Description: "Monitor and control communications at the external managed interfaces to the system and at key internal managed interfaces within the system.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"SI-3": {
		ID:          "SI-3",
		Family:      "System and Information Integrity",
		Name:        "Malicious Code Protection",
		Description: "Implement malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"SI-4": {
		ID:          "SI-4",
		Family:      "System and Information Integrity",
		Name:        "System Monitoring",
		Description: "Monitor the system to detect attacks, indicators of potential attacks, and unauthorized local, network, and remote connections.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"SI-10": {
		ID:          "SI-10",
		Family:      "System and Information Integrity",
		Name:        "Information Input Validation",
		Description: "Check the validity of information inputs to the system to verify inputs match specified definitions for format and content.",
		Priority:    "P1",
		Baseline:    []string{"Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"AC-3": {
		ID:          "AC-3",
		Family:      "Access Control",
		Name:        "Access Enforcement",
		Description: "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"AC-6": {
		ID:          "AC-6",
		Family:      "Access Control",
		Name:        "Least Privilege",
		Description: "Employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned organizational tasks.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"IA-2": {
		ID:          "IA-2",
		Family:      "Identification and Authentication",
		Name:        "Identification and Authentication (Organizational Users)",
		Description: "Uniquely identify and authenticate organizational users and associate that unique identification with processes acting on behalf of those users.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"IA-5": {
		ID:          "IA-5",
		Family:      "Identification and Authentication",
		Name:        "Authenticator Management",
		Description: "Manage system authenticators by verifying identity before initial distribution, establishing initial content, ensuring administrative activities, and protecting against unauthorized disclosure.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"AU-6": {
		ID:          "AU-6",
		Family:      "Audit and Accountability",
		Name:        "Audit Record Review, Analysis, and Reporting",
		Description: "Review and analyze system audit records for indications of inappropriate or unusual activity and report findings.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"CP-9": {
		ID:          "CP-9",
		Family:      "Contingency Planning",
		Name:        "System Backup",
		Description: "Conduct backups of user-level and system-level information contained in the system on a defined frequency.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
	"CP-10": {
		ID:          "CP-10",
		Family:      "Contingency Planning",
		Name:        "System Recovery and Reconstitution",
		Description: "Provide for the recovery and reconstitution of the system to a known state within organization-defined time period.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "NIST 800-53",
	},
}

// CWEToControlMapping maps common CWE patterns to applicable controls
var CWEToControlMapping = map[string][]string{
	// Injection vulnerabilities
	"CWE-78":  {"SI-2", "SI-10", "SC-7"},         // OS Command Injection
	"CWE-79":  {"SI-2", "SI-10"},                 // Cross-site Scripting (XSS)
	"CWE-89":  {"SI-2", "SI-10"},                 // SQL Injection
	"CWE-94":  {"SI-2", "SI-10", "SC-7"},         // Code Injection
	"CWE-77":  {"SI-2", "SI-10", "SC-7"},         // Command Injection

	// Authentication/Authorization
	"CWE-287": {"IA-2", "IA-5", "SI-2"},          // Improper Authentication
	"CWE-306": {"AC-3", "AC-6", "SI-2"},          // Missing Auth for Critical Function
	"CWE-862": {"AC-3", "AC-6", "SI-2"},          // Missing Authorization
	"CWE-863": {"AC-3", "AC-6", "SI-2"},          // Incorrect Authorization
	"CWE-269": {"AC-6", "SI-2"},                  // Improper Privilege Management

	// Memory/Buffer vulnerabilities
	"CWE-120": {"SI-2", "SI-4"},                  // Buffer Overflow
	"CWE-122": {"SI-2", "SI-4"},                  // Heap-based Buffer Overflow
	"CWE-787": {"SI-2", "SI-4"},                  // Out-of-bounds Write
	"CWE-416": {"SI-2", "SI-4"},                  // Use After Free
	"CWE-125": {"SI-2", "SI-4"},                  // Out-of-bounds Read

	// Path/File vulnerabilities
	"CWE-22":  {"SI-2", "AC-3", "AC-6"},          // Path Traversal
	"CWE-434": {"SI-2", "AC-3", "SI-10"},         // Unrestricted Upload

	// Deserialization
	"CWE-502": {"SI-2", "SI-10", "SC-7"},         // Deserialization of Untrusted Data

	// Information Exposure
	"CWE-200": {"SI-2", "AC-3", "AU-6"},          // Exposure of Sensitive Information
	"CWE-532": {"SI-2", "AU-6"},                  // Log Exposure

}

// FedRAMPControls contains FedRAMP-specific control mappings
// These are largely based on NIST 800-53 but with FedRAMP-specific baselines
var FedRAMPControls = map[string]SecurityControl{
	"SI-2": {
		ID:          "SI-2",
		Family:      "System and Information Integrity",
		Name:        "Flaw Remediation",
		Description: "High-impact vulnerabilities must be remediated within 30 days. Critical vulnerabilities within 15 days for FedRAMP systems.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "FedRAMP",
	},
	"RA-5": {
		ID:          "RA-5",
		Family:      "Risk Assessment",
		Name:        "Vulnerability Monitoring and Scanning",
		Description: "Perform vulnerability scans at least monthly and within 72 hours of new vulnerability disclosure for FedRAMP systems.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "FedRAMP",
	},
	"IR-4": {
		ID:          "IR-4",
		Family:      "Incident Response",
		Name:        "Incident Handling",
		Description: "Report incidents to US-CERT within 1 hour of identification for FedRAMP systems.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "FedRAMP",
	},
	"CA-7": {
		ID:          "CA-7",
		Family:      "Assessment, Authorization, and Monitoring",
		Name:        "Continuous Monitoring",
		Description: "Implement continuous monitoring per FedRAMP ConMon requirements including monthly vulnerability scans and annual assessments.",
		Priority:    "P1",
		Baseline:    []string{"Low", "Moderate", "High"},
		Framework:   "FedRAMP",
	},
}
