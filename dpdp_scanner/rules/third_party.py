from __future__ import annotations

import re
from typing import Dict, List


# Third-party classification by DPDP risk level
HIGH_RISK_SDK_PATTERNS = {
    "analytics": [
        r"mixpanel", r"segment", r"amplitude", r"posthog",
        r"fullstory", r"heap\.io", r"hotjar", r"clarity",
        r"logrocket", r"smartlook",
    ],
    "marketing": [
        r"mailchimp", r"klaviyo", r"hubspot", r"brevo",
        r"sendinblue", r"activecampaign", r"marketo",
        r"salesforce.*marketing",
    ],
    "profiling": [
        r"facebook.*pixel", r"fb\.init\b", r"gtag\b",
        r"google.*analytics", r"ga4\b",
    ],
}

MEDIUM_RISK_SDK_PATTERNS = {
    "communication": [
        r"twilio", r"msg91", r"sendgrid", r"resend",
        r"postmark", r"mailgun",
    ],
    "support": [
        r"intercom", r"zendesk", r"freshdesk", r"crisp",
        r"tawk\.to", r"drift",
    ],
    "monitoring": [
        r"sentry", r"bugsnag", r"rollbar", r"datadog",
        r"newrelic", r"raygun",
    ],
}

LOW_RISK_SDK_PATTERNS = {
    "payment": [
        r"stripe", r"razorpay", r"payu", r"cashfree",
        r"phonepe", r"braintree", r"paypal",
    ],
    "auth": [
        r"auth0", r"okta", r"cognito", r"firebase.*auth",
        r"supertokens",
    ],
}


def _classify_sdk(library_name: str) -> tuple[str, str]:
    """
    Returns (category, risk_level) for a third-party SDK.
    risk_level: 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'
    """
    name = library_name.lower()
    for category, patterns in HIGH_RISK_SDK_PATTERNS.items():
        if any(re.search(p, name) for p in patterns):
            return category, "HIGH"
    for category, patterns in MEDIUM_RISK_SDK_PATTERNS.items():
        if any(re.search(p, name) for p in patterns):
            return category, "MEDIUM"
    for category, patterns in LOW_RISK_SDK_PATTERNS.items():
        if any(re.search(p, name) for p in patterns):
            return category, "LOW"
    return "unknown", "MEDIUM"


SEVERITY_DESCRIPTIONS = {
    ("analytics", "HIGH"): (
        "Personal data present in file that imports an analytics/tracking SDK. "
        "DPDP Section 6 requires explicit analytics consent separate from "
        "functional consent. Section 5 requires disclosure in privacy notice."
    ),
    ("marketing", "HIGH"): (
        "Personal data present in file that imports a marketing platform SDK. "
        "Email and profile data sent to marketing platforms requires explicit "
        "marketing consent under DPDP Section 6."
    ),
    ("profiling", "HIGH"): (
        "Personal data present in file importing a behavioral profiling SDK. "
        "User profiling requires explicit consent under DPDP Section 6 and "
        "must be disclosed in the privacy notice under Section 5."
    ),
    ("communication", "MEDIUM"): (
        "Personal data flows to a communication/email service SDK. "
        "Ensure a data processing agreement is in place and users are "
        "notified in the privacy policy under DPDP Section 5."
    ),
    ("support", "MEDIUM"): (
        "Personal data flows to a customer support platform. "
        "Ensure DPA with provider and disclose in privacy notice."
    ),
    ("monitoring", "MEDIUM"): (
        "Personal data may flow to error monitoring service. "
        "Ensure PII is scrubbed from error reports before transmission. "
        "DPDP Section 8(1) requires appropriate security measures."
    ),
    ("payment", "LOW"): (
        "Personal data flows to payment processor. "
        "Payment processing is likely contractual necessity under Section 7. "
        "Verify DPA with processor and that only necessary data is transmitted."
    ),
    ("auth", "LOW"): (
        "Personal data flows to authentication provider. "
        "Auth provider integration is typically Section 7 legitimate use. "
        "Verify DPA and that tokens/sessions are handled securely."
    ),
}


def check_third_party(extracted: Dict) -> List[Dict]:
    pii_fields = extracted.get("pii_fields", []) or []
    third_party_imports = extracted.get("third_party_imports", []) or []
    findings: List[Dict] = []

    if not third_party_imports:
        findings.append({
            "rule": "NO_THIRD_PARTY_DETECTED",
            "dpdp_section": "Section 5 — Notice",
            "severity": "INFO",
            "confidence": 0.90,
            "file": "N/A",
            "evidence": {},
            "description": "No known third-party analytics or tracking SDKs detected in codebase.",
            "fix": None,
        })
        return findings

    pii_files = {item.get("file") for item in pii_fields if item.get("file")}
    third_party_files = {item.get("file") for item in third_party_imports if item.get("file")}
    overlap = pii_files & third_party_files

    for file_path in sorted(overlap):
        libs_in_file = [i for i in third_party_imports if i.get("file") == file_path]
        pii_in_file = [i for i in pii_fields if i.get("file") == file_path]

        highest_severity = "MEDIUM"
        highest_category = "unknown"
        sdk_names = [l.get("library", l.get("name", "")) for l in libs_in_file]

        for sdk_name in sdk_names:
            category, risk = _classify_sdk(sdk_name)
            if risk == "HIGH":
                highest_severity = "HIGH"
                highest_category = category
                break
            elif risk == "MEDIUM" and highest_severity != "HIGH":
                highest_severity = "MEDIUM"
                highest_category = category
            elif risk == "LOW" and highest_severity not in ("HIGH", "MEDIUM"):
                highest_severity = "LOW"
                highest_category = category

        description = SEVERITY_DESCRIPTIONS.get(
            (highest_category, highest_severity),
            "Personal data present in file that imports third-party SDK. "
            "Data may be shared without user awareness or notice (DPDP Section 5).",
        )

        confidence = {"HIGH": 0.80, "MEDIUM": 0.65, "LOW": 0.55}.get(highest_severity, 0.65)

        findings.append({
            "rule": "THIRD_PARTY_PII_SHARING",
            "dpdp_section": "Section 5 — Notice",
            "severity": highest_severity,
            "confidence": confidence,
            "file": file_path,
            "evidence": {
                "libraries": libs_in_file,
                "pii_fields": pii_in_file[:5],
                "sdk_category": highest_category,
                "line_numbers": [i.get("line_number") for i in libs_in_file if i.get("line_number")],
            },
            "description": description,
            "fix": [
                "Disclose this third-party data sharing in your privacy notice under Section 5.",
                "Obtain explicit user consent for analytics/marketing use under Section 6 if applicable.",
                "Ensure a Data Processing Agreement is in place with the provider.",
                "Implement data minimization — only send fields necessary for the SDK's purpose.",
            ],
        })

    return findings
