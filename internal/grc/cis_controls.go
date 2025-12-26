package grc

// CIS Controls v8 Implementation
// https://www.cisecurity.org/controls/v8

// CISControl represents a CIS Critical Security Control
type CISControl struct {
	ID               string `json:"id"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	IG1              bool   `json:"implementation_group_1"` // Basic Cyber Hygiene
	IG2              bool   `json:"implementation_group_2"` // Medium enterprise
	IG3              bool   `json:"implementation_group_3"` // Large enterprise
	AssetType        string `json:"asset_type"`             // Devices, Data, Users, etc.
	SecurityFunction string `json:"security_function"`      // Identify, Protect, Detect, Respond, Recover
}

// CISControls is the map of all CIS Controls v8
var CISControls = map[string]CISControl{
	// Control 1: Inventory and Control of Enterprise Assets
	"1.1": {
		ID:               "1.1",
		Title:            "Establish and Maintain Detailed Enterprise Asset Inventory",
		Description:      "Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Devices",
		SecurityFunction: "Identify",
	},
	"1.2": {
		ID:               "1.2",
		Title:            "Address Unauthorized Assets",
		Description:      "Ensure that a process exists to address unauthorized assets on a weekly basis.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Devices",
		SecurityFunction: "Respond",
	},

	// Control 2: Inventory and Control of Software Assets
	"2.1": {
		ID:               "2.1",
		Title:            "Establish and Maintain a Software Inventory",
		Description:      "Establish and maintain a detailed inventory of all licensed software installed on enterprise assets.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Identify",
	},
	"2.2": {
		ID:               "2.2",
		Title:            "Ensure Authorized Software is Currently Supported",
		Description:      "Ensure that only currently supported software is designated as authorized.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Identify",
	},
	"2.3": {
		ID:               "2.3",
		Title:            "Address Unauthorized Software",
		Description:      "Ensure that unauthorized software is either removed or the inventory is updated in a timely manner.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Respond",
	},

	// Control 3: Data Protection
	"3.1": {
		ID:               "3.1",
		Title:            "Establish and Maintain a Data Management Process",
		Description:      "Establish and maintain a data management process including data sensitivity levels.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Data",
		SecurityFunction: "Identify",
	},
	"3.4": {
		ID:               "3.4",
		Title:            "Enforce Data Retention",
		Description:      "Retain data according to the enterprise's data management process.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Data",
		SecurityFunction: "Protect",
	},

	// Control 4: Secure Configuration of Enterprise Assets and Software
	"4.1": {
		ID:               "4.1",
		Title:            "Establish and Maintain a Secure Configuration Process",
		Description:      "Establish and maintain a secure configuration process for enterprise assets and software.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Protect",
	},
	"4.7": {
		ID:               "4.7",
		Title:            "Manage Default Accounts on Enterprise Assets and Software",
		Description:      "Manage default accounts on enterprise assets and software.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Protect",
	},

	// Control 5: Account Management
	"5.1": {
		ID:               "5.1",
		Title:            "Establish and Maintain an Inventory of Accounts",
		Description:      "Establish and maintain an inventory of all accounts managed in the enterprise.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Identify",
	},
	"5.3": {
		ID:               "5.3",
		Title:            "Disable Dormant Accounts",
		Description:      "Delete or disable any dormant accounts after a period of 45 days of inactivity.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Protect",
	},
	"5.4": {
		ID:               "5.4",
		Title:            "Restrict Administrator Privileges to Dedicated Administrator Accounts",
		Description:      "Restrict administrator privileges to dedicated administrator accounts on enterprise assets.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Protect",
	},

	// Control 6: Access Control Management
	"6.1": {
		ID:               "6.1",
		Title:            "Establish an Access Granting Process",
		Description:      "Establish and follow a process for granting access to enterprise assets and software.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Protect",
	},
	"6.2": {
		ID:               "6.2",
		Title:            "Establish an Access Revoking Process",
		Description:      "Establish and follow a process for revoking access to enterprise assets and software.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Protect",
	},
	"6.5": {
		ID:               "6.5",
		Title:            "Require MFA for Administrative Access",
		Description:      "Require MFA for all administrative access accounts.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Protect",
	},

	// Control 7: Continuous Vulnerability Management
	"7.1": {
		ID:               "7.1",
		Title:            "Establish and Maintain a Vulnerability Management Process",
		Description:      "Establish and maintain a documented vulnerability management process for enterprise assets.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Identify",
	},
	"7.2": {
		ID:               "7.2",
		Title:            "Establish and Maintain a Remediation Process",
		Description:      "Establish and maintain a risk-based remediation strategy documented in a remediation process.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Respond",
	},
	"7.3": {
		ID:               "7.3",
		Title:            "Perform Automated Operating System Patch Management",
		Description:      "Perform operating system updates on enterprise assets through automated patch management.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Devices",
		SecurityFunction: "Protect",
	},
	"7.4": {
		ID:               "7.4",
		Title:            "Perform Automated Application Patch Management",
		Description:      "Perform application updates on enterprise assets through automated patch management.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Protect",
	},
	"7.5": {
		ID:               "7.5",
		Title:            "Perform Automated Vulnerability Scans of Internal Enterprise Assets",
		Description:      "Perform automated vulnerability scans of internal enterprise assets on a quarterly basis.",
		IG2:              true,
		IG3:              true,
		AssetType:        "Devices",
		SecurityFunction: "Detect",
	},
	"7.6": {
		ID:               "7.6",
		Title:            "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets",
		Description:      "Perform automated vulnerability scans of externally-exposed enterprise assets.",
		IG2:              true,
		IG3:              true,
		AssetType:        "Devices",
		SecurityFunction: "Detect",
	},
	"7.7": {
		ID:               "7.7",
		Title:            "Remediate Detected Vulnerabilities",
		Description:      "Remediate detected vulnerabilities in software through processes and tooling on a monthly basis.",
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Respond",
	},

	// Control 8: Audit Log Management
	"8.1": {
		ID:               "8.1",
		Title:            "Establish and Maintain an Audit Log Management Process",
		Description:      "Establish and maintain an audit log management process that defines logging requirements.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Network",
		SecurityFunction: "Detect",
	},
	"8.2": {
		ID:               "8.2",
		Title:            "Collect Audit Logs",
		Description:      "Collect audit logs from enterprise assets.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Network",
		SecurityFunction: "Detect",
	},

	// Control 9: Email and Web Browser Protections
	"9.1": {
		ID:               "9.1",
		Title:            "Ensure Use of Only Fully Supported Browsers and Email Clients",
		Description:      "Ensure only fully supported browsers and email clients are allowed to execute.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Protect",
	},

	// Control 10: Malware Defenses
	"10.1": {
		ID:               "10.1",
		Title:            "Deploy and Maintain Anti-Malware Software",
		Description:      "Deploy and maintain anti-malware software on all enterprise assets.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Devices",
		SecurityFunction: "Protect",
	},
	"10.2": {
		ID:               "10.2",
		Title:            "Configure Automatic Anti-Malware Signature Updates",
		Description:      "Configure automatic updates for anti-malware signature files.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Devices",
		SecurityFunction: "Protect",
	},
	"10.7": {
		ID:               "10.7",
		Title:            "Use Behavior-Based Anti-Malware Software",
		Description:      "Use behavior-based anti-malware software.",
		IG2:              true,
		IG3:              true,
		AssetType:        "Devices",
		SecurityFunction: "Detect",
	},

	// Control 11: Data Recovery
	"11.1": {
		ID:               "11.1",
		Title:            "Establish and Maintain a Data Recovery Process",
		Description:      "Establish and maintain a data recovery process including scope of recovery activities.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Data",
		SecurityFunction: "Recover",
	},
	"11.2": {
		ID:               "11.2",
		Title:            "Perform Automated Backups",
		Description:      "Perform automated backups of in-scope enterprise assets.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Data",
		SecurityFunction: "Recover",
	},
	"11.4": {
		ID:               "11.4",
		Title:            "Establish and Maintain an Isolated Instance of Recovery Data",
		Description:      "Establish and maintain an isolated instance of recovery data using offline or cloud storage.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Data",
		SecurityFunction: "Recover",
	},

	// Control 12: Network Infrastructure Management
	"12.1": {
		ID:               "12.1",
		Title:            "Ensure Network Infrastructure is Up-to-Date",
		Description:      "Ensure network infrastructure is kept up-to-date.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Network",
		SecurityFunction: "Protect",
	},

	// Control 13: Network Monitoring and Defense
	"13.1": {
		ID:               "13.1",
		Title:            "Centralize Security Event Alerting",
		Description:      "Centralize security event alerting across enterprise assets.",
		IG2:              true,
		IG3:              true,
		AssetType:        "Network",
		SecurityFunction: "Detect",
	},

	// Control 14: Security Awareness and Skills Training
	"14.1": {
		ID:               "14.1",
		Title:            "Establish and Maintain a Security Awareness Program",
		Description:      "Establish and maintain a security awareness program.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Protect",
	},
	"14.2": {
		ID:               "14.2",
		Title:            "Train Workforce Members to Recognize Social Engineering Attacks",
		Description:      "Train workforce members to recognize social engineering attacks.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Protect",
	},

	// Control 15: Service Provider Management
	"15.1": {
		ID:               "15.1",
		Title:            "Establish and Maintain an Inventory of Service Providers",
		Description:      "Establish and maintain an inventory of service providers.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Network",
		SecurityFunction: "Identify",
	},

	// Control 16: Application Software Security
	"16.1": {
		ID:               "16.1",
		Title:            "Establish and Maintain a Secure Application Development Process",
		Description:      "Establish and maintain a secure application development process.",
		IG2:              true,
		IG3:              true,
		AssetType:        "Applications",
		SecurityFunction: "Protect",
	},

	// Control 17: Incident Response Management
	"17.1": {
		ID:               "17.1",
		Title:            "Designate Personnel to Manage Incident Handling",
		Description:      "Designate one key person, and at least one backup, to manage incident handling.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Respond",
	},
	"17.2": {
		ID:               "17.2",
		Title:            "Establish and Maintain Contact Information for Reporting Security Incidents",
		Description:      "Establish and maintain contact information for reporting security incidents.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Respond",
	},
	"17.3": {
		ID:               "17.3",
		Title:            "Establish and Maintain an Enterprise Process for Reporting Incidents",
		Description:      "Establish and maintain an enterprise process for the workforce to report security incidents.",
		IG1:              true,
		IG2:              true,
		IG3:              true,
		AssetType:        "Users",
		SecurityFunction: "Respond",
	},

	// Control 18: Penetration Testing
	"18.1": {
		ID:               "18.1",
		Title:            "Establish and Maintain a Penetration Testing Program",
		Description:      "Establish and maintain a penetration testing program appropriate to the size and complexity.",
		IG2:              true,
		IG3:              true,
		AssetType:        "Network",
		SecurityFunction: "Identify",
	},
}

// CWEToCISMapping maps CWE types to relevant CIS Controls
var CWEToCISMapping = map[string][]string{
	// Injection flaws
	"CWE-78":  {"7.1", "7.2", "7.3", "7.4", "4.1", "16.1"}, // OS Command Injection
	"CWE-79":  {"7.1", "7.2", "9.1", "16.1"},               // XSS
	"CWE-89":  {"7.1", "7.2", "16.1", "4.1"},               // SQL Injection
	"CWE-94":  {"7.1", "7.2", "7.4", "16.1"},               // Code Injection
	"CWE-502": {"7.1", "7.2", "16.1", "4.1"},               // Deserialization

	// Authentication/Authorization
	"CWE-287": {"5.1", "5.3", "5.4", "6.1", "6.2", "6.5"}, // Improper Auth
	"CWE-269": {"5.4", "6.1", "6.2"},                      // Improper Privilege Mgmt
	"CWE-352": {"9.1", "16.1"},                            // CSRF

	// Memory Safety
	"CWE-119": {"7.1", "7.2", "7.3", "7.4", "2.2"}, // Buffer Overflow
	"CWE-787": {"7.1", "7.2", "7.3", "7.4"},        // Out-of-bounds Write
	"CWE-416": {"7.1", "7.2", "7.3", "7.4"},        // Use After Free

	// Information Disclosure
	"CWE-200": {"3.1", "3.4", "8.1", "8.2"}, // Information Exposure

	// Configuration
	"CWE-434": {"4.1", "9.1", "16.1"},  // Unrestricted Upload
	"CWE-611": {"4.1", "16.1"},         // XXE
	"CWE-918": {"4.1", "12.1", "16.1"}, // SSRF
}

// GetCISControl returns a CIS Control by ID
func GetCISControl(id string) (CISControl, bool) {
	control, ok := CISControls[id]
	return control, ok
}

// GetCISControlsForCWE returns CIS Controls applicable to a CWE
func GetCISControlsForCWE(cwe string) []CISControl {
	controlIDs, ok := CWEToCISMapping[cwe]
	if !ok {
		// Return base vulnerability management controls
		controlIDs = []string{"7.1", "7.2", "7.3", "7.4"}
	}

	var controls []CISControl
	for _, id := range controlIDs {
		if ctrl, ok := CISControls[id]; ok {
			controls = append(controls, ctrl)
		}
	}
	return controls
}

// ListCISControlsByIG returns controls for a specific Implementation Group
func ListCISControlsByIG(ig int) []CISControl {
	var controls []CISControl
	for _, ctrl := range CISControls {
		switch ig {
		case 1:
			if ctrl.IG1 {
				controls = append(controls, ctrl)
			}
		case 2:
			if ctrl.IG2 {
				controls = append(controls, ctrl)
			}
		case 3:
			if ctrl.IG3 {
				controls = append(controls, ctrl)
			}
		}
	}
	return controls
}

// ListCISControlsByFunction returns controls by security function (NIST CSF alignment)
func ListCISControlsByFunction(function string) []CISControl {
	var controls []CISControl
	for _, ctrl := range CISControls {
		if ctrl.SecurityFunction == function {
			controls = append(controls, ctrl)
		}
	}
	return controls
}
