# Phishing-Analysis-
Analysis of phishing email send by a user
Phishing Indicators Report
Objective:
To analyze a suspicious email and identify characteristics commonly associated with phishing attempts using free tools and manual inspection.
________________________________________
Email Sample Summary
•	Subject: Urgent: Your Account Will Be Locked!
•	Sender Email Address: security-update@amazn-alert.com
•	Date Received: May 25, 2025
•	Attachment(s): Account_Update_Form.pdf
•	Email Client: Outlook Web App (OWA)
________________________________________
1. Sender Email Address Analysis
•	Observation: The sender's domain is amazn-alert.com, which is not associated with the legitimate Amazon domain (amazon.com).
•	Phishing Indicator:
o	Domain misspelling (typosquatting) intended to deceive recipients into thinking it's from Amazon.
o	Use of hyphenated and non-standard domain names often correlates with phishing.
o	This technique is used to bypass naive domain filters and trick users who scan emails quickly.
________________________________________
2. Email Header Analysis
•	Tool Used: MXToolbox Header Analyzer / Google Admin Toolbox
•	Key Header Findings:
o	SPF (Sender Policy Framework): Fail
	The sender domain’s SPF record does not authorize the sending IP.
o	DKIM (DomainKeys Identified Mail): Not signed
	The message was not cryptographically signed with DKIM, raising authenticity concerns.
o	Received From IP: 176.223.133.29 (hosted in Eastern Europe by an unknown VPS provider)
o	Reply-To Address: support@unknown-domain.ru, different from the “From” address.
•	Phishing Indicators:
o	Failed SPF check indicates possible spoofing.
o	No DKIM signature – reduces email authenticity.
o	Mismatched Reply-To domain – common tactic to redirect responses to attacker.
o	Hosting origin from suspicious region, unrelated to sender domain.
________________________________________
3. URL and Hyperlink Analysis
•	Link Displayed: “Click here to verify your account”
•	Actual Link: http://secure-amazon-login.xyz/verify
•	Method: Hovered over link to reveal URL.
•	Phishing Indicators:
o	Displayed text and actual URL do not match.
o	URL uses a deceptive domain (secure-amazon-login.xyz), attempting to mimic Amazon.
o	Usage of HTTP instead of HTTPS – insecure and suspicious.
o	Suspicious TLD (.xyz) commonly used in malicious domains.
________________________________________
4. Language and Psychological Tactics
•	Email Excerpt:
“We detected unauthorized access to your account. If you don’t confirm your identity within 24 hours, your Amazon account will be permanently suspended.”
•	Phishing Indicators:
o	Use of urgency and fear to prompt immediate action without scrutiny.
o	Common social engineering tactic used to bypass user judgment.
________________________________________
5. Spelling and Grammar Errors
•	Examples Identified:
o	“Your acount need verifycation immediately.”
o	“Click hear to proced to secure page.”
•	Phishing Indicators:
o	Repeated spelling and grammatical errors reflect lack of professionalism.
o	Legitimate companies typically review customer-facing communications thoroughly.
________________________________________
6. Attachment Analysis
•	File Name: Account_Update_Form.pdf
•	Inspection Result:
o	The PDF requests personal information including:
	Full Name
	Address
	Date of Birth
	Credit Card Number
	Social Security Number
o	Phishing Indicators:
	Legitimate companies never ask for sensitive information via downloadable forms.
	This could also potentially be a malicious payload containing exploit scripts or data exfiltration code.
________________________________________
7. Additional Red Flags
•	No personal salutation – generic greeting: “Dear customer”
•	Lack of official branding – low-resolution logo, off-brand fonts
•	No digital signature – missing common security features like message authentication codes or company-specific footer.
________________________________________
Final Assessment and Conclusion
Based on the comprehensive analysis, the email contains numerous strong indicators of a phishing attempt, including:
•	Spoofed and deceptive sender address
•	SPF authentication failure
•	Mismatched and suspicious URLs
•	Use of threatening and urgent language
•	Obvious grammar/spelling issues
•	A fraudulent attachment soliciting sensitive data
•	Overall lack of professionalism and branding
Threat Level: HIGH
Action Recommended: Do NOT open any attachments or click any links. Report to your organization's cybersecurity team or email provider. Block the sender domain and related IP addresses.
________________________________________
Tools Used
•	MXToolbox Email Header Analyzer: https://mxtoolbox.com/EmailHeaders.aspx
•	Google Admin Toolbox (Messageheader): https://toolbox.googleapps.com/apps/messageheader/
•	VirusTotal URL Scanner: https://www.virustotal.com
•	PhishTank Verification: https://www.phishtank.com/

