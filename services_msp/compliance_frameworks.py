"""
AITHER Platform - Compliance Frameworks Service
Pre-built compliance framework templates for MSP operations.

Provides HIPAA, SOC2, NIST 800-171, CMMC Level 2, and PCI-DSS v4.0
compliance checklists that MSPs can deploy for client assessments.

G-47: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.compliance import (
        ComplianceFrameworkTemplateModel,
        ComplianceControlTemplateModel,
        ComplianceAssessmentModel as AssessmentORM,
        ComplianceFindingModel as FindingORM,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class ControlStatus(str, Enum):
    NOT_ASSESSED = "not_assessed"
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class Control:
    """A single compliance control within a framework."""
    control_id: str
    framework_id: str
    control_number: str
    title: str
    description: str
    category: str
    requirement_text: str
    evidence_types: List[str] = field(default_factory=list)
    automated_check: bool = False
    status: str = ControlStatus.NOT_ASSESSED
    notes: str = ""
    last_assessed: Optional[datetime] = None
    assessed_by: str = ""


@dataclass
class Framework:
    """A compliance framework template."""
    framework_id: str
    name: str
    version: str
    description: str
    controls: List[Control] = field(default_factory=list)
    total_controls: int = 0


@dataclass
class Finding:
    """A compliance finding from an assessment."""
    finding_id: str
    assessment_id: str
    control_id: str
    severity: str = FindingSeverity.MEDIUM
    description: str = ""
    recommendation: str = ""
    due_date: Optional[datetime] = None
    status: str = FindingStatus.OPEN
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ComplianceAssessment:
    """A client compliance assessment against a framework."""
    assessment_id: str
    client_id: str
    framework_id: str
    assessed_by: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    overall_score: float = 0.0
    controls_compliant: int = 0
    controls_non_compliant: int = 0
    controls_partial: int = 0
    controls_na: int = 0
    controls_not_assessed: int = 0
    findings: List[Finding] = field(default_factory=list)
    control_statuses: Dict[str, str] = field(default_factory=dict)


# ============================================================
# Pre-built Framework Data
# ============================================================

def _build_hipaa_controls(framework_id: str) -> List[Control]:
    """HIPAA Security Rule controls - 45 CFR Part 164."""
    raw = [
        ("164.308(a)(1)(i)", "Security Management Process", "Administrative Safeguards",
         "Implement policies and procedures to prevent, detect, contain, and correct security violations.",
         "Covered entities must implement a security management process.", ["policy_document", "risk_assessment", "audit_log"], True),
        ("164.308(a)(1)(ii)(A)", "Risk Analysis", "Administrative Safeguards",
         "Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI.",
         "Risk analysis must identify threats to confidentiality, integrity, and availability of ePHI.", ["risk_assessment", "vulnerability_scan"], True),
        ("164.308(a)(1)(ii)(B)", "Risk Management", "Administrative Safeguards",
         "Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable level.",
         "Implement measures to reduce identified risks to acceptable levels.", ["risk_treatment_plan", "remediation_evidence"], False),
        ("164.308(a)(1)(ii)(C)", "Sanction Policy", "Administrative Safeguards",
         "Apply appropriate sanctions against workforce members who fail to comply with security policies.",
         "Documented sanction policy must exist and be communicated to workforce.", ["policy_document", "training_records"], False),
        ("164.308(a)(1)(ii)(D)", "Information System Activity Review", "Administrative Safeguards",
         "Implement procedures to regularly review records of information system activity.",
         "Regular review of audit logs, access reports, and security incident tracking.", ["audit_log", "review_records"], True),
        ("164.308(a)(2)", "Assigned Security Responsibility", "Administrative Safeguards",
         "Identify the security official responsible for developing and implementing security policies.",
         "A single individual must be designated as the security officer.", ["organizational_chart", "appointment_letter"], False),
        ("164.308(a)(3)(i)", "Workforce Security", "Administrative Safeguards",
         "Implement policies to ensure all workforce members have appropriate access to ePHI.",
         "Only authorized workforce members should have access to ePHI.", ["access_control_list", "hr_records", "termination_checklist"], True),
        ("164.308(a)(3)(ii)(A)", "Authorization and Supervision", "Administrative Safeguards",
         "Implement procedures for authorizing access to ePHI consistent with the clearance procedure.",
         "Workforce access must be authorized and supervised.", ["access_request_forms", "supervisor_approvals"], False),
        ("164.308(a)(3)(ii)(B)", "Workforce Clearance Procedure", "Administrative Safeguards",
         "Implement procedures to determine appropriate access to ePHI for workforce members.",
         "Background checks and clearance procedures for ePHI access.", ["background_check_records", "clearance_documentation"], False),
        ("164.308(a)(3)(ii)(C)", "Termination Procedures", "Administrative Safeguards",
         "Implement procedures for terminating access to ePHI when employment ends.",
         "Access must be revoked upon termination of employment.", ["termination_checklist", "access_revocation_log"], True),
        ("164.308(a)(4)(i)", "Information Access Management", "Administrative Safeguards",
         "Implement policies for authorizing access to ePHI consistent with applicable requirements.",
         "Access management policies must align with the minimum necessary standard.", ["access_policy", "role_definitions"], False),
        ("164.308(a)(4)(ii)(A)", "Isolating Healthcare Clearinghouse Functions", "Administrative Safeguards",
         "Clearinghouse must isolate ePHI processing from other operations if part of a larger organization.",
         "Healthcare clearinghouse functions must be logically isolated.", ["network_diagram", "access_controls"], False),
        ("164.308(a)(4)(ii)(B)", "Access Authorization", "Administrative Safeguards",
         "Implement policies for granting access to ePHI, e.g. through workstations, transactions, programs.",
         "Formal access authorization process for ePHI systems.", ["access_request_forms", "approval_workflow"], False),
        ("164.308(a)(4)(ii)(C)", "Access Establishment and Modification", "Administrative Safeguards",
         "Implement policies for establishing, documenting, reviewing, and modifying access to ePHI.",
         "Procedures for provisioning and modifying user access.", ["provisioning_records", "access_reviews"], True),
        ("164.308(a)(5)(i)", "Security Awareness and Training", "Administrative Safeguards",
         "Implement a security awareness and training program for all workforce members.",
         "All workforce members must receive security awareness training.", ["training_records", "training_materials", "attendance_logs"], False),
        ("164.308(a)(5)(ii)(A)", "Security Reminders", "Administrative Safeguards",
         "Periodic security updates and reminders to workforce.",
         "Regular security reminders via newsletters, bulletins, or other communications.", ["communication_records", "reminder_logs"], False),
        ("164.308(a)(5)(ii)(B)", "Protection from Malicious Software", "Administrative Safeguards",
         "Procedures for guarding against, detecting, and reporting malicious software.",
         "Anti-malware procedures and training.", ["antivirus_reports", "training_records"], True),
        ("164.308(a)(5)(ii)(C)", "Log-in Monitoring", "Administrative Safeguards",
         "Procedures for monitoring log-in attempts and reporting discrepancies.",
         "Monitor and report failed login attempts.", ["login_audit_logs", "alert_configurations"], True),
        ("164.308(a)(5)(ii)(D)", "Password Management", "Administrative Safeguards",
         "Procedures for creating, changing, and safeguarding passwords.",
         "Password policies and management procedures.", ["password_policy", "system_configurations"], True),
        ("164.308(a)(6)(i)", "Security Incident Procedures", "Administrative Safeguards",
         "Implement policies to address security incidents.",
         "Formal incident response procedures must be documented.", ["incident_response_plan", "incident_reports"], False),
        ("164.308(a)(6)(ii)", "Response and Reporting", "Administrative Safeguards",
         "Identify and respond to suspected or known security incidents; mitigate effects and document.",
         "Incident response and reporting procedures.", ["incident_reports", "remediation_records", "notification_records"], False),
        ("164.308(a)(7)(i)", "Contingency Plan", "Administrative Safeguards",
         "Establish policies for responding to emergencies that damage systems containing ePHI.",
         "Business continuity and disaster recovery plans for ePHI systems.", ["contingency_plan", "test_results"], False),
        ("164.308(a)(7)(ii)(A)", "Data Backup Plan", "Administrative Safeguards",
         "Establish procedures to create and maintain retrievable exact copies of ePHI.",
         "Regular backup procedures for ePHI.", ["backup_logs", "restoration_test_results"], True),
        ("164.308(a)(8)", "Evaluation", "Administrative Safeguards",
         "Perform periodic technical and nontechnical evaluation in response to changes.",
         "Periodic security evaluations of policies and procedures.", ["evaluation_reports", "audit_results"], False),
        ("164.310(a)(1)", "Facility Access Controls", "Physical Safeguards",
         "Implement policies to limit physical access to ePHI systems and the facilities they reside in.",
         "Physical access controls to facilities housing ePHI.", ["access_logs", "facility_security_plan", "badge_records"], False),
        ("164.310(b)", "Workstation Use", "Physical Safeguards",
         "Implement policies specifying proper functions, physical attributes, and surroundings of workstations.",
         "Workstation use policies for accessing ePHI.", ["workstation_policy", "configuration_standards"], False),
        ("164.310(c)", "Workstation Security", "Physical Safeguards",
         "Implement physical safeguards for all workstations that access ePHI.",
         "Physical security of workstations accessing ePHI.", ["physical_security_assessment", "workstation_inventory"], False),
        ("164.310(d)(1)", "Device and Media Controls", "Physical Safeguards",
         "Implement policies governing receipt and removal of hardware and electronic media containing ePHI.",
         "Controls for hardware and media containing ePHI.", ["media_inventory", "disposal_records", "encryption_verification"], False),
        ("164.312(a)(1)", "Access Control", "Technical Safeguards",
         "Implement technical policies to allow access only to authorized persons or software programs.",
         "Technical access controls for ePHI systems.", ["access_control_lists", "system_configurations", "rbac_documentation"], True),
        ("164.312(a)(2)(i)", "Unique User Identification", "Technical Safeguards",
         "Assign a unique name and/or number for identifying and tracking user identity.",
         "Unique user IDs for all ePHI system users.", ["user_directory", "system_configurations"], True),
        ("164.312(a)(2)(ii)", "Emergency Access Procedure", "Technical Safeguards",
         "Establish procedures for obtaining necessary ePHI during an emergency.",
         "Break-glass procedures for emergency ePHI access.", ["emergency_access_procedure", "test_results"], False),
        ("164.312(a)(2)(iii)", "Automatic Logoff", "Technical Safeguards",
         "Implement procedures that terminate an electronic session after a predetermined time of inactivity.",
         "Automatic session timeout on ePHI systems.", ["system_configurations", "timeout_settings"], True),
        ("164.312(a)(2)(iv)", "Encryption and Decryption", "Technical Safeguards",
         "Implement a mechanism to encrypt and decrypt ePHI.",
         "Encryption of ePHI at rest and in transit.", ["encryption_configurations", "certificate_inventory"], True),
        ("164.312(b)", "Audit Controls", "Technical Safeguards",
         "Implement hardware, software, and/or procedural mechanisms to record and examine activity.",
         "Audit logging on all systems containing ePHI.", ["audit_log_configurations", "sample_audit_logs", "review_records"], True),
        ("164.312(c)(1)", "Integrity", "Technical Safeguards",
         "Implement policies to protect ePHI from improper alteration or destruction.",
         "Data integrity controls for ePHI.", ["integrity_controls", "hash_verification", "change_detection"], True),
        ("164.312(c)(2)", "Mechanism to Authenticate ePHI", "Technical Safeguards",
         "Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed.",
         "ePHI authentication mechanisms (checksums, digital signatures).", ["integrity_verification_logs"], True),
        ("164.312(d)", "Person or Entity Authentication", "Technical Safeguards",
         "Implement procedures to verify that a person or entity seeking access to ePHI is who they claim to be.",
         "Authentication mechanisms for ePHI access.", ["mfa_configuration", "authentication_logs"], True),
        ("164.312(e)(1)", "Transmission Security", "Technical Safeguards",
         "Implement technical measures to guard against unauthorized access to ePHI being transmitted.",
         "Encryption and integrity controls for ePHI in transit.", ["tls_configurations", "vpn_configurations", "network_diagrams"], True),
        ("164.312(e)(2)(i)", "Integrity Controls", "Technical Safeguards",
         "Implement security measures to ensure ePHI is not improperly modified during transmission.",
         "Transmission integrity verification.", ["tls_certificates", "integrity_check_logs"], True),
        ("164.312(e)(2)(ii)", "Encryption", "Technical Safeguards",
         "Implement encryption for ePHI transmissions whenever deemed appropriate.",
         "Encryption of ePHI transmissions.", ["encryption_standards", "tls_scan_results"], True),
    ]
    controls = []
    for i, (num, title, cat, desc, req, evidence, auto) in enumerate(raw):
        controls.append(Control(
            control_id=f"hipaa-{i+1:03d}",
            framework_id=framework_id,
            control_number=num,
            title=title,
            description=desc,
            category=cat,
            requirement_text=req,
            evidence_types=evidence,
            automated_check=auto,
        ))
    return controls


def _build_soc2_controls(framework_id: str) -> List[Control]:
    """SOC 2 Trust Services Criteria controls."""
    raw = [
        ("CC1.1", "COSO Principle 1: Integrity and Ethical Values", "Control Environment",
         "The entity demonstrates a commitment to integrity and ethical values.",
         "Management sets the tone at the top regarding integrity and ethics.", ["code_of_conduct", "ethics_policy", "training_records"], False),
        ("CC1.2", "COSO Principle 2: Board Independence and Oversight", "Control Environment",
         "The board of directors demonstrates independence from management and exercises oversight.",
         "Board oversight of internal controls and risk management.", ["board_minutes", "committee_charters"], False),
        ("CC1.3", "COSO Principle 3: Management Structure and Authority", "Control Environment",
         "Management establishes structures, reporting lines, and authorities.",
         "Organizational structure supports accountability.", ["org_chart", "job_descriptions", "delegation_of_authority"], False),
        ("CC1.4", "COSO Principle 4: Commitment to Competence", "Control Environment",
         "The entity demonstrates commitment to attract, develop, and retain competent individuals.",
         "HR policies ensure competent personnel.", ["hr_policies", "performance_reviews", "training_plans"], False),
        ("CC1.5", "COSO Principle 5: Accountability", "Control Environment",
         "The entity holds individuals accountable for their internal control responsibilities.",
         "Accountability structures for control responsibilities.", ["performance_metrics", "corrective_actions"], False),
        ("CC2.1", "COSO Principle 13: Quality Information", "Communication and Information",
         "The entity obtains or generates and uses relevant, quality information.",
         "Information systems produce quality data for decision-making.", ["data_quality_reports", "system_documentation"], False),
        ("CC2.2", "COSO Principle 14: Internal Communication", "Communication and Information",
         "The entity internally communicates information necessary to support internal control functioning.",
         "Internal communication of control-relevant information.", ["communication_policies", "meeting_minutes", "dashboards"], False),
        ("CC2.3", "COSO Principle 15: External Communication", "Communication and Information",
         "The entity communicates with external parties regarding matters affecting internal control.",
         "External communication of security commitments.", ["customer_agreements", "vendor_contracts", "privacy_notices"], False),
        ("CC3.1", "COSO Principle 6: Risk Identification", "Risk Assessment",
         "The entity specifies objectives with sufficient clarity to enable identification of risks.",
         "Clear objectives enable risk identification.", ["risk_register", "objective_documentation"], False),
        ("CC3.2", "COSO Principle 7: Risk Analysis", "Risk Assessment",
         "The entity identifies risks to achievement of objectives and analyzes them.",
         "Risk analysis process covering likelihood and impact.", ["risk_assessments", "threat_models"], False),
        ("CC3.3", "COSO Principle 8: Fraud Risk", "Risk Assessment",
         "The entity considers the potential for fraud in assessing risks.",
         "Fraud risk assessment process.", ["fraud_risk_assessment", "anti_fraud_controls"], False),
        ("CC3.4", "COSO Principle 9: Change Impact", "Risk Assessment",
         "The entity identifies and assesses changes that could impact internal control.",
         "Change management considers impact on internal controls.", ["change_impact_assessments", "change_logs"], False),
        ("CC5.1", "COSO Principle 10: Control Activities Selection", "Control Activities",
         "The entity selects and develops control activities that mitigate risks.",
         "Controls selected based on risk assessment results.", ["control_matrix", "risk_treatment_plans"], False),
        ("CC5.2", "COSO Principle 11: Technology Controls", "Control Activities",
         "The entity selects and develops general control activities over technology.",
         "IT general controls over infrastructure and applications.", ["itgc_documentation", "system_configurations", "access_reviews"], True),
        ("CC5.3", "COSO Principle 12: Control Policies", "Control Activities",
         "The entity deploys controls through policies and procedures.",
         "Documented policies and procedures implement controls.", ["policy_library", "procedure_documents", "version_control"], False),
        ("CC6.1", "Logical Access Security", "Logical and Physical Access",
         "The entity implements logical access security controls over protected information assets.",
         "Logical access controls restrict unauthorized access.", ["access_control_policies", "rbac_configuration", "access_reviews"], True),
        ("CC6.2", "System Credentials and Access", "Logical and Physical Access",
         "Prior to issuing system credentials, the entity registers and authorizes new users.",
         "User provisioning and credential management.", ["provisioning_procedures", "approval_records", "user_directory"], True),
        ("CC6.3", "Role-Based Access", "Logical and Physical Access",
         "The entity authorizes, modifies, or removes access based on roles and responsibilities.",
         "Role-based access control implementation.", ["rbac_matrix", "access_modification_logs", "periodic_access_reviews"], True),
        ("CC6.4", "Physical Access Restrictions", "Logical and Physical Access",
         "The entity restricts physical access to facilities and protected assets.",
         "Physical access controls to data centers and offices.", ["physical_access_logs", "badge_records", "visitor_logs"], False),
        ("CC6.5", "Asset Disposal", "Logical and Physical Access",
         "The entity discontinues logical and physical protections over assets only after disposal.",
         "Secure asset disposal procedures.", ["disposal_records", "certificate_of_destruction", "wipe_logs"], False),
        ("CC6.6", "Threat Protection", "Logical and Physical Access",
         "The entity implements controls to prevent or detect and act upon unauthorized or malicious threats.",
         "Threat detection and prevention systems.", ["firewall_rules", "ids_ips_logs", "siem_configurations"], True),
        ("CC6.7", "Data Transmission Protection", "Logical and Physical Access",
         "The entity restricts the transmission, movement, and removal of information.",
         "Controls over data in transit and data movement.", ["dlp_policies", "encryption_standards", "transfer_logs"], True),
        ("CC6.8", "Unauthorized Software Prevention", "Logical and Physical Access",
         "The entity implements controls to prevent or detect unauthorized or malicious software.",
         "Application whitelisting and malware protection.", ["antimalware_reports", "application_whitelist", "scan_results"], True),
        ("CC7.1", "Infrastructure Monitoring", "System Operations",
         "The entity detects configuration changes and monitors infrastructure and software.",
         "Continuous monitoring of IT infrastructure.", ["monitoring_dashboards", "alert_configurations", "change_detection_logs"], True),
        ("CC7.2", "Anomaly Detection", "System Operations",
         "The entity monitors system components for anomalies indicating malicious acts or natural disasters.",
         "Anomaly and event detection systems.", ["siem_alerts", "anomaly_reports", "threat_intelligence_feeds"], True),
        ("CC7.3", "Security Incident Evaluation", "System Operations",
         "The entity evaluates security events to determine whether they constitute incidents.",
         "Security event triage and incident determination.", ["triage_procedures", "incident_classifications"], False),
        ("CC7.4", "Incident Response", "System Operations",
         "The entity responds to identified security incidents by executing a defined process.",
         "Incident response plan and execution.", ["incident_response_plan", "incident_reports", "post_mortems"], False),
        ("CC7.5", "Incident Recovery", "System Operations",
         "The entity identifies, develops, and implements activities to recover from incidents.",
         "Recovery procedures and lessons learned.", ["recovery_plans", "restoration_logs", "lessons_learned"], False),
        ("CC8.1", "Change Management", "Change Management",
         "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes.",
         "Formal change management process.", ["change_requests", "test_results", "approval_records", "deployment_logs"], True),
        ("CC9.1", "Risk Identification and Assessment", "Risk Mitigation",
         "The entity identifies, selects, and develops risk mitigation activities.",
         "Risk mitigation strategy and implementation.", ["risk_treatment_plans", "mitigation_evidence"], False),
        ("CC9.2", "Vendor Risk Management", "Risk Mitigation",
         "The entity assesses and manages risks associated with vendors and business partners.",
         "Third-party risk management program.", ["vendor_assessments", "vendor_contracts", "soc_reports"], False),
    ]
    controls = []
    for i, (num, title, cat, desc, req, evidence, auto) in enumerate(raw):
        controls.append(Control(
            control_id=f"soc2-{i+1:03d}",
            framework_id=framework_id,
            control_number=num,
            title=title,
            description=desc,
            category=cat,
            requirement_text=req,
            evidence_types=evidence,
            automated_check=auto,
        ))
    return controls


def _build_nist_800_171_controls(framework_id: str) -> List[Control]:
    """NIST SP 800-171 Rev 2 controls for CUI protection."""
    raw = [
        ("3.1.1", "Limit system access to authorized users", "Access Control",
         "Limit information system access to authorized users, processes, or devices.",
         "Access must be limited to authorized users and processes acting on behalf of authorized users.", ["access_policy", "user_directory", "system_configurations"], True),
        ("3.1.2", "Limit system access to authorized functions", "Access Control",
         "Limit information system access to the types of transactions and functions that authorized users are permitted.",
         "Function-level access control enforcement.", ["rbac_matrix", "function_access_controls"], True),
        ("3.1.3", "Control CUI flow", "Access Control",
         "Control the flow of CUI in accordance with approved authorizations.",
         "Information flow controls for CUI.", ["data_flow_diagrams", "dlp_policies", "network_segmentation"], True),
        ("3.1.4", "Separation of duties", "Access Control",
         "Separate the duties of individuals to reduce the risk of malevolent activity.",
         "Separation of duties for critical functions.", ["role_definitions", "sod_matrix", "access_reviews"], False),
        ("3.1.5", "Least privilege", "Access Control",
         "Employ the principle of least privilege, including for specific security functions.",
         "Least privilege access for all users and processes.", ["access_reviews", "privilege_analysis", "admin_account_inventory"], True),
        ("3.2.1", "Security awareness training", "Awareness and Training",
         "Ensure that managers and users are made aware of security risks associated with their activities.",
         "Security awareness training for all personnel.", ["training_records", "training_materials", "completion_reports"], False),
        ("3.2.2", "Role-based security training", "Awareness and Training",
         "Ensure that personnel are trained to carry out their assigned security-related duties.",
         "Role-specific security training.", ["role_training_plans", "certification_records"], False),
        ("3.3.1", "System audit logging", "Audit and Accountability",
         "Create, protect, and retain system audit logs and records.",
         "Audit logging enabled on all CUI systems.", ["audit_configurations", "log_retention_policies", "sample_logs"], True),
        ("3.3.2", "Individual accountability", "Audit and Accountability",
         "Ensure that the actions of individual users can be uniquely traced.",
         "User actions must be attributable to individuals.", ["audit_logs", "user_attribution_evidence"], True),
        ("3.4.1", "Configuration baselines", "Configuration Management",
         "Establish and maintain baseline configurations and inventories of organizational systems.",
         "Documented system baselines and asset inventory.", ["baseline_configurations", "asset_inventory", "cmdb_records"], True),
        ("3.4.2", "Security configuration enforcement", "Configuration Management",
         "Establish and enforce security configuration settings for IT products.",
         "Security hardening standards enforced.", ["hardening_guides", "compliance_scan_results", "gpo_configurations"], True),
        ("3.5.1", "User identification", "Identification and Authentication",
         "Identify information system users, processes, or devices.",
         "Unique identification for all users and devices.", ["user_directory", "device_certificates", "service_accounts"], True),
        ("3.5.2", "Authentication mechanisms", "Identification and Authentication",
         "Authenticate users, processes, or devices as a prerequisite to access.",
         "Multi-factor authentication for CUI systems.", ["mfa_configurations", "authentication_policies"], True),
        ("3.6.1", "Incident handling", "Incident Response",
         "Establish an operational incident-handling capability.",
         "Incident response plan and trained team.", ["incident_response_plan", "team_roster", "contact_lists"], False),
        ("3.6.2", "Incident reporting", "Incident Response",
         "Track, document, and report incidents to appropriate officials.",
         "Incident tracking and reporting procedures.", ["incident_tracking_system", "reporting_templates", "notification_records"], False),
        ("3.7.1", "System maintenance", "Maintenance",
         "Perform maintenance on organizational information systems.",
         "Controlled maintenance procedures.", ["maintenance_logs", "maintenance_schedules", "vendor_records"], False),
        ("3.7.2", "Maintenance tool control", "Maintenance",
         "Provide effective controls on tools, techniques, mechanisms, and personnel used for maintenance.",
         "Authorized maintenance tools and personnel.", ["tool_inventory", "personnel_authorization"], False),
        ("3.8.1", "Media protection", "Media Protection",
         "Protect information system media containing CUI, both paper and digital.",
         "Media handling and protection controls.", ["media_policy", "encryption_verification", "handling_procedures"], False),
        ("3.8.3", "Media sanitization", "Media Protection",
         "Sanitize or destroy information system media containing CUI before disposal.",
         "Media sanitization procedures.", ["sanitization_records", "certificate_of_destruction"], False),
        ("3.9.1", "Personnel screening", "Personnel Security",
         "Screen individuals prior to authorizing access to systems containing CUI.",
         "Background screening for CUI access.", ["screening_records", "clearance_documentation"], False),
        ("3.9.2", "CUI protection during personnel actions", "Personnel Security",
         "Ensure that CUI is protected during and after personnel actions such as terminations.",
         "Access revocation upon personnel changes.", ["termination_checklists", "access_revocation_logs"], True),
        ("3.10.1", "Physical access limitations", "Physical Protection",
         "Limit physical access to organizational systems, equipment, and operating environments.",
         "Physical access controls to CUI processing areas.", ["physical_access_logs", "access_control_mechanisms"], False),
        ("3.10.2", "Physical access monitoring", "Physical Protection",
         "Protect and monitor the physical facility and support infrastructure.",
         "Physical facility monitoring systems.", ["cctv_records", "guard_logs", "alarm_systems"], False),
        ("3.11.1", "Risk assessments", "Risk Assessment",
         "Periodically assess the risk to organizational operations and assets.",
         "Regular risk assessments for CUI systems.", ["risk_assessments", "threat_analysis", "vulnerability_assessments"], False),
        ("3.11.2", "Vulnerability scanning", "Risk Assessment",
         "Scan for vulnerabilities in organizational systems periodically and when new vulnerabilities are identified.",
         "Regular vulnerability scanning.", ["vulnerability_scan_reports", "remediation_tracking"], True),
        ("3.12.1", "Security assessments", "Security Assessment",
         "Periodically assess security controls to determine if controls are effective.",
         "Periodic security control assessments.", ["assessment_reports", "pen_test_results", "audit_findings"], False),
        ("3.13.1", "Boundary protection", "System and Communications Protection",
         "Monitor, control, and protect communications at external boundaries and key internal boundaries.",
         "Network boundary protection.", ["firewall_rules", "network_diagrams", "ids_ips_configurations"], True),
        ("3.13.8", "CUI encryption in transit", "System and Communications Protection",
         "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission.",
         "Encryption of CUI in transit.", ["tls_configurations", "vpn_configurations", "encryption_standards"], True),
        ("3.13.11", "FIPS-validated cryptography", "System and Communications Protection",
         "Employ FIPS-validated cryptography when used to protect confidentiality of CUI.",
         "FIPS 140-2 validated encryption for CUI.", ["fips_certificates", "cryptographic_module_inventory"], True),
        ("3.14.1", "Flaw remediation", "System and Information Integrity",
         "Identify, report, and correct information system flaws in a timely manner.",
         "Patch management and flaw remediation.", ["patch_management_reports", "vulnerability_tracking", "remediation_timelines"], True),
        ("3.14.2", "Malicious code protection", "System and Information Integrity",
         "Provide protection from malicious code at appropriate locations.",
         "Anti-malware and endpoint protection.", ["antimalware_configurations", "scan_reports", "signature_update_logs"], True),
        ("3.14.3", "Security alerts and advisories", "System and Information Integrity",
         "Monitor system security alerts and advisories and take appropriate actions.",
         "Security advisory monitoring and response.", ["advisory_tracking", "response_records", "patch_priorities"], True),
    ]
    controls = []
    for i, (num, title, cat, desc, req, evidence, auto) in enumerate(raw):
        controls.append(Control(
            control_id=f"nist171-{i+1:03d}",
            framework_id=framework_id,
            control_number=num,
            title=title,
            description=desc,
            category=cat,
            requirement_text=req,
            evidence_types=evidence,
            automated_check=auto,
        ))
    return controls


def _build_cmmc_controls(framework_id: str) -> List[Control]:
    """CMMC Level 2 controls (maps to NIST 800-171)."""
    raw = [
        ("AC.L2-3.1.1", "Authorized Access Control", "Access Control",
         "Limit information system access to authorized users, processes acting on behalf of authorized users, and devices.",
         "Maps to NIST 800-171 3.1.1. Only authorized users, processes, and devices may access systems.", ["access_policy", "user_directory"], True),
        ("AC.L2-3.1.2", "Transaction and Function Control", "Access Control",
         "Limit information system access to the types of transactions and functions that authorized users are permitted to execute.",
         "Maps to NIST 800-171 3.1.2. Function-level access enforcement.", ["rbac_matrix", "function_controls"], True),
        ("AC.L2-3.1.3", "CUI Flow Enforcement", "Access Control",
         "Control the flow of CUI in accordance with approved authorizations.",
         "Maps to NIST 800-171 3.1.3. Data flow controls for CUI.", ["data_flow_diagrams", "dlp_policies"], True),
        ("AC.L2-3.1.5", "Least Privilege", "Access Control",
         "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
         "Maps to NIST 800-171 3.1.5. Minimal necessary access.", ["privilege_analysis", "access_reviews"], True),
        ("AC.L2-3.1.7", "Privileged Function Restrictions", "Access Control",
         "Prevent non-privileged users from executing privileged functions.",
         "Privileged function execution restricted to authorized administrators.", ["admin_controls", "uac_configuration"], True),
        ("AT.L2-3.2.1", "Role-Based Risk Awareness", "Awareness and Training",
         "Ensure that managers, systems administrators, and users are aware of the security risks.",
         "Maps to NIST 800-171 3.2.1. Security risk awareness training.", ["training_records", "awareness_materials"], False),
        ("AT.L2-3.2.2", "Role-Based Training", "Awareness and Training",
         "Ensure that personnel are trained to carry out their assigned information security-related duties.",
         "Maps to NIST 800-171 3.2.2. Role-specific training.", ["training_plans", "completion_certificates"], False),
        ("AU.L2-3.3.1", "System Auditing", "Audit and Accountability",
         "Create and retain system audit logs and records to enable monitoring, analysis, investigation, and reporting.",
         "Maps to NIST 800-171 3.3.1. Audit logging on all CUI systems.", ["audit_configurations", "log_samples"], True),
        ("AU.L2-3.3.2", "User Accountability", "Audit and Accountability",
         "Ensure that the actions of individual system users can be uniquely traced.",
         "Maps to NIST 800-171 3.3.2. Individual user accountability.", ["audit_logs", "user_activity_reports"], True),
        ("CM.L2-3.4.1", "System Baselining", "Configuration Management",
         "Establish and maintain baseline configurations and inventories of organizational systems.",
         "Maps to NIST 800-171 3.4.1. System baselines and asset inventory.", ["baseline_configs", "asset_inventory"], True),
        ("CM.L2-3.4.2", "Security Configuration Enforcement", "Configuration Management",
         "Establish and enforce security configuration settings for information technology products.",
         "Maps to NIST 800-171 3.4.2. Hardening standards enforcement.", ["hardening_guides", "scan_results"], True),
        ("IA.L2-3.5.1", "Identification", "Identification and Authentication",
         "Identify information system users, processes acting on behalf of users, and devices.",
         "Maps to NIST 800-171 3.5.1. Unique identification.", ["user_directory", "device_certs"], True),
        ("IA.L2-3.5.2", "Authentication", "Identification and Authentication",
         "Authenticate (or verify) the identities of users, processes, or devices.",
         "Maps to NIST 800-171 3.5.2. Multi-factor authentication.", ["mfa_configuration", "authentication_policies"], True),
        ("IR.L2-3.6.1", "Incident Handling", "Incident Response",
         "Establish an operational incident-handling capability for organizational systems.",
         "Maps to NIST 800-171 3.6.1. Incident response capability.", ["ir_plan", "team_roster"], False),
        ("IR.L2-3.6.2", "Incident Reporting", "Incident Response",
         "Track, document, and report incidents to designated officials and/or authorities.",
         "Maps to NIST 800-171 3.6.2. Incident tracking and reporting.", ["incident_reports", "notification_records"], False),
        ("SC.L2-3.13.1", "Boundary Protection", "System and Communications Protection",
         "Monitor, control, and protect communications at external boundaries and key internal boundaries.",
         "Maps to NIST 800-171 3.13.1. Network boundary controls.", ["firewall_rules", "network_diagrams"], True),
        ("SC.L2-3.13.8", "CUI Encryption in Transit", "System and Communications Protection",
         "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission.",
         "Maps to NIST 800-171 3.13.8. Encryption in transit.", ["tls_configurations", "encryption_standards"], True),
        ("SC.L2-3.13.11", "FIPS-Validated Cryptography", "System and Communications Protection",
         "Employ FIPS-validated cryptography when used to protect confidentiality of CUI.",
         "Maps to NIST 800-171 3.13.11. FIPS 140-2 validated crypto.", ["fips_certificates", "crypto_inventory"], True),
        ("SI.L2-3.14.1", "Flaw Remediation", "System and Information Integrity",
         "Identify, report, and correct information and information system flaws in a timely manner.",
         "Maps to NIST 800-171 3.14.1. Patch management.", ["patch_reports", "vulnerability_tracking"], True),
        ("SI.L2-3.14.2", "Malicious Code Protection", "System and Information Integrity",
         "Provide protection from malicious code at designated locations.",
         "Maps to NIST 800-171 3.14.2. Endpoint protection.", ["antimalware_config", "scan_reports"], True),
        ("SI.L2-3.14.3", "Security Alerts", "System and Information Integrity",
         "Monitor system security alerts and advisories and take action in response.",
         "Maps to NIST 800-171 3.14.3. Advisory monitoring.", ["advisory_tracking", "response_logs"], True),
    ]
    controls = []
    for i, (num, title, cat, desc, req, evidence, auto) in enumerate(raw):
        controls.append(Control(
            control_id=f"cmmc-{i+1:03d}",
            framework_id=framework_id,
            control_number=num,
            title=title,
            description=desc,
            category=cat,
            requirement_text=req,
            evidence_types=evidence,
            automated_check=auto,
        ))
    return controls


def _build_pci_dss_controls(framework_id: str) -> List[Control]:
    """PCI-DSS v4.0 requirements."""
    raw = [
        ("1.1", "Install and Maintain Network Security Controls", "Build and Maintain a Secure Network",
         "Processes and mechanisms for installing and maintaining network security controls are defined and understood.",
         "Network security controls (firewalls, routers) must be installed and maintained.", ["firewall_rules", "network_diagrams", "change_logs"], True),
        ("1.2", "Network Security Controls Configuration", "Build and Maintain a Secure Network",
         "Network security controls are configured and maintained.",
         "Restrict connections between untrusted networks and the CDE.", ["firewall_configs", "ruleset_reviews", "network_segmentation_tests"], True),
        ("1.3", "Network Access Restrictions to CDE", "Build and Maintain a Secure Network",
         "Network access to and from the cardholder data environment is restricted.",
         "Inbound and outbound traffic restricted to that which is necessary.", ["acl_configs", "traffic_flow_analysis"], True),
        ("2.1", "Secure Configuration Standards", "Build and Maintain a Secure Network",
         "Processes and mechanisms for applying secure configurations are defined and understood.",
         "Vendor-supplied defaults must be changed before installation.", ["hardening_standards", "configuration_baselines"], True),
        ("2.2", "System Component Configuration", "Build and Maintain a Secure Network",
         "System components are configured and managed securely.",
         "Security configuration standards for all system components.", ["hardening_guides", "compliance_scans", "change_management_records"], True),
        ("3.1", "Account Data Storage Minimization", "Protect Account Data",
         "Processes and mechanisms for protecting stored account data are defined and understood.",
         "Cardholder data storage must be kept to a minimum.", ["data_retention_policy", "data_inventory", "disposal_records"], False),
        ("3.4", "Render PAN Unreadable", "Protect Account Data",
         "Access to displays of full PAN and ability to copy cardholder data are restricted.",
         "PAN must be rendered unreadable anywhere it is stored.", ["encryption_configurations", "tokenization_evidence", "masking_rules"], True),
        ("3.5", "Primary Account Number Protection", "Protect Account Data",
         "Primary account number (PAN) is secured wherever it is stored.",
         "PAN protection mechanisms (encryption, truncation, tokenization, or hashing).", ["encryption_keys", "key_management_procedures"], True),
        ("4.1", "Strong Cryptography for Transmission", "Encrypt Transmission of Cardholder Data",
         "Processes and mechanisms for protecting cardholder data with strong cryptography during transmission are defined.",
         "Strong cryptography for cardholder data transmitted over open, public networks.", ["tls_configurations", "certificate_inventory", "scan_results"], True),
        ("4.2", "PAN Protection During Transmission", "Encrypt Transmission of Cardholder Data",
         "PAN is protected with strong cryptography during transmission.",
         "Encryption of PAN over all networks including internal.", ["network_encryption_configs", "tls_scan_results"], True),
        ("5.1", "Malicious Software Prevention", "Maintain a Vulnerability Management Program",
         "Processes and mechanisms for protecting all systems from malicious software are defined and understood.",
         "Deploy anti-malware on all systems commonly affected by malware.", ["antimalware_policy", "deployment_evidence"], True),
        ("5.2", "Malicious Software Detection and Prevention", "Maintain a Vulnerability Management Program",
         "Malicious software is prevented or detected and addressed.",
         "Anti-malware solutions must be kept current and active.", ["antimalware_scan_logs", "update_records", "alert_configurations"], True),
        ("5.3", "Anti-Malware Mechanisms Active", "Maintain a Vulnerability Management Program",
         "Anti-malware mechanisms and processes are active, maintained, and monitored.",
         "Anti-malware cannot be disabled by users without management authorization.", ["policy_enforcement", "tamper_protection_logs"], True),
        ("6.1", "Secure Development Processes", "Develop and Maintain Secure Systems",
         "Processes and mechanisms for developing and maintaining secure systems and software are defined and understood.",
         "Security vulnerability identification and management.", ["vulnerability_management_process", "vendor_patch_tracking"], True),
        ("6.2", "Secure Software Development", "Develop and Maintain Secure Systems",
         "Bespoke and custom software is developed securely.",
         "Secure coding practices and code review.", ["sdlc_documentation", "code_review_records", "security_testing_results"], False),
        ("6.3", "Security Vulnerabilities Identified and Addressed", "Develop and Maintain Secure Systems",
         "Security vulnerabilities are identified and addressed.",
         "Critical patches installed within one month of release.", ["patch_management_reports", "vulnerability_scans"], True),
        ("7.1", "Access Control Mechanisms", "Implement Strong Access Control Measures",
         "Processes and mechanisms for restricting access to system components and cardholder data are defined.",
         "Access limited to individuals whose job requires it.", ["access_control_policy", "need_to_know_documentation"], False),
        ("7.2", "Access Appropriately Defined and Assigned", "Implement Strong Access Control Measures",
         "Access to system components and data is appropriately defined and assigned.",
         "Role-based access control for CDE.", ["rbac_matrix", "access_reviews", "approval_records"], True),
        ("8.1", "User Identification and Authentication", "Implement Strong Access Control Measures",
         "Processes and mechanisms for identifying users and authenticating access are defined and managed.",
         "Unique ID assigned to each person with computer access.", ["user_directory", "id_management_policy"], True),
        ("8.3", "Strong Authentication for Users and Administrators", "Implement Strong Access Control Measures",
         "Strong authentication for users and administrators is established and managed.",
         "Multi-factor authentication for CDE access.", ["mfa_configuration", "authentication_logs", "password_policy"], True),
        ("8.6", "Application and System Account Management", "Implement Strong Access Control Measures",
         "Use of application and system accounts is strictly managed.",
         "Shared and service accounts controlled and documented.", ["service_account_inventory", "account_management_procedures"], True),
        ("9.1", "Physical Access to Cardholder Data Restricted", "Restrict Physical Access",
         "Processes and mechanisms for restricting physical access to cardholder data are defined and understood.",
         "Appropriate facility entry controls to limit physical access.", ["physical_access_policy", "entry_controls", "badge_systems"], False),
        ("10.1", "Logging and Monitoring", "Track and Monitor Access",
         "Processes and mechanisms for logging and monitoring are defined and understood.",
         "Audit trails to link access to individual users.", ["audit_log_configurations", "monitoring_procedures"], True),
        ("10.2", "Audit Logs Implemented", "Track and Monitor Access",
         "Audit logs are implemented to support detection of anomalies and suspicious activity.",
         "Audit logs for all system components in CDE.", ["log_configurations", "sample_audit_logs", "siem_integration"], True),
        ("10.4", "Audit Logs Reviewed", "Track and Monitor Access",
         "Audit logs are reviewed to identify anomalies or suspicious activity.",
         "Daily log review process.", ["log_review_procedures", "review_records", "alert_response_logs"], True),
        ("11.1", "Wireless Access Point Testing", "Regularly Test Security Systems",
         "Processes and mechanisms for regularly testing security of systems and networks are defined.",
         "Test for unauthorized wireless access points quarterly.", ["wireless_scan_results", "rogue_ap_reports"], True),
        ("11.3", "Vulnerability Scanning", "Regularly Test Security Systems",
         "External and internal vulnerabilities are regularly identified, prioritized, and addressed.",
         "Internal and external vulnerability scans at least quarterly.", ["vulnerability_scan_reports", "remediation_tracking"], True),
        ("11.4", "Penetration Testing", "Regularly Test Security Systems",
         "External and internal penetration testing is regularly performed.",
         "Annual penetration testing of CDE.", ["pen_test_reports", "remediation_evidence"], False),
        ("12.1", "Information Security Policy", "Maintain an Information Security Policy",
         "A comprehensive information security policy is established, published, maintained, and disseminated.",
         "Security policy that addresses all PCI DSS requirements.", ["security_policy", "distribution_records", "acknowledgements"], False),
        ("12.6", "Security Awareness Program", "Maintain an Information Security Policy",
         "Security awareness education is an ongoing activity.",
         "Formal security awareness program for all personnel.", ["training_records", "awareness_materials", "completion_tracking"], False),
        ("12.8", "Third-Party Service Provider Management", "Maintain an Information Security Policy",
         "Risk to information assets from relationships with third-party service providers is managed.",
         "Policies for managing service providers.", ["tpsp_policy", "provider_agreements", "compliance_monitoring"], False),
        ("12.10", "Incident Response Plan", "Maintain an Information Security Policy",
         "Suspected and confirmed security incidents are responded to immediately.",
         "Incident response plan covering card data breaches.", ["ir_plan", "team_contacts", "test_results", "notification_procedures"], False),
    ]
    controls = []
    for i, (num, title, cat, desc, req, evidence, auto) in enumerate(raw):
        controls.append(Control(
            control_id=f"pci-{i+1:03d}",
            framework_id=framework_id,
            control_number=num,
            title=title,
            description=desc,
            category=cat,
            requirement_text=req,
            evidence_types=evidence,
            automated_check=auto,
        ))
    return controls


# ============================================================
# Shield-to-Control Mapping
# ============================================================

SHIELD_EVENT_CONTROL_MAP: Dict[str, List[str]] = {
    "malware_detected": [
        "hipaa-017", "soc2-021", "soc2-023", "nist171-031",
        "cmmc-020", "pci-012", "pci-013",
    ],
    "unauthorized_access": [
        "hipaa-029", "hipaa-037", "soc2-016", "soc2-017",
        "nist171-001", "cmmc-001", "pci-019", "pci-020",
    ],
    "data_exfiltration": [
        "hipaa-038", "soc2-022", "nist171-003",
        "cmmc-003", "pci-009", "pci-010",
    ],
    "failed_login_attempts": [
        "hipaa-018", "hipaa-037", "soc2-016",
        "nist171-013", "cmmc-013", "pci-020",
    ],
    "encryption_failure": [
        "hipaa-033", "hipaa-039", "hipaa-040",
        "soc2-022", "nist171-028", "nist171-029",
        "cmmc-017", "cmmc-018", "pci-009", "pci-010",
    ],
    "unpatched_vulnerability": [
        "nist171-030", "cmmc-019", "pci-016",
        "soc2-014", "hipaa-001",
    ],
    "firewall_breach": [
        "soc2-021", "nist171-027", "cmmc-016",
        "pci-001", "pci-002", "pci-003",
    ],
    "audit_log_tampering": [
        "hipaa-034", "soc2-024", "soc2-025",
        "nist171-008", "nist171-009", "cmmc-008", "cmmc-009",
        "pci-023", "pci-024",
    ],
    "phishing_attempt": [
        "hipaa-015", "hipaa-016", "soc2-021",
        "nist171-006", "cmmc-006", "pci-030",
    ],
    "configuration_drift": [
        "nist171-010", "nist171-011", "cmmc-010", "cmmc-011",
        "pci-004", "pci-005", "soc2-014",
    ],
}


# ============================================================
# Service
# ============================================================

class ComplianceFrameworkService:
    """
    Compliance Framework Template Service.

    Pre-loads HIPAA, SOC2, NIST 800-171, CMMC Level 2, and PCI-DSS v4.0
    framework templates. MSPs can start assessments against these frameworks
    for any client.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback
        self._frameworks: Dict[str, Framework] = {}
        self._assessments: Dict[str, ComplianceAssessment] = {}
        self._findings: Dict[str, Finding] = {}

        # Load pre-built frameworks
        self._load_frameworks()

    # --------------------------------------------------------
    # Framework Loading
    # --------------------------------------------------------

    def _load_frameworks(self):
        """Load all pre-built compliance frameworks."""
        builders = [
            ("fw-hipaa", "HIPAA Security Rule", "45 CFR 164", "Health Insurance Portability and Accountability Act - Security Rule", _build_hipaa_controls),
            ("fw-soc2", "SOC 2 Type II", "2017", "Service Organization Control 2 - Trust Services Criteria", _build_soc2_controls),
            ("fw-nist-171", "NIST SP 800-171", "Rev 2", "Protecting Controlled Unclassified Information in Nonfederal Systems", _build_nist_800_171_controls),
            ("fw-cmmc", "CMMC Level 2", "v2.0", "Cybersecurity Maturity Model Certification - Level 2", _build_cmmc_controls),
            ("fw-pci-dss", "PCI-DSS", "v4.0", "Payment Card Industry Data Security Standard", _build_pci_dss_controls),
        ]
        for fw_id, name, version, desc, builder_fn in builders:
            controls = builder_fn(fw_id)
            fw = Framework(
                framework_id=fw_id,
                name=name,
                version=version,
                description=desc,
                controls=controls,
                total_controls=len(controls),
            )
            self._frameworks[fw_id] = fw

        # Persist to DB if available
        if self._use_db:
            self._sync_frameworks_to_db()

    def _sync_frameworks_to_db(self):
        """Sync in-memory frameworks to DB (upsert)."""
        try:
            for fw in self._frameworks.values():
                existing = self.db.query(ComplianceFrameworkTemplateModel).filter(
                    ComplianceFrameworkTemplateModel.framework_id == fw.framework_id
                ).first()
                if not existing:
                    orm_fw = ComplianceFrameworkTemplateModel(
                        framework_id=fw.framework_id,
                        name=fw.name,
                        version=fw.version,
                        description=fw.description,
                        total_controls=fw.total_controls,
                    )
                    self.db.add(orm_fw)
                    self.db.flush()

                    for ctrl in fw.controls:
                        orm_ctrl = ComplianceControlTemplateModel(
                            control_id=ctrl.control_id,
                            framework_id=ctrl.framework_id,
                            control_number=ctrl.control_number,
                            title=ctrl.title,
                            description=ctrl.description,
                            category=ctrl.category,
                            requirement_text=ctrl.requirement_text,
                            evidence_types=ctrl.evidence_types,
                            automated_check=ctrl.automated_check,
                        )
                        self.db.add(orm_ctrl)
            self.db.commit()
        except Exception as e:
            logger.warning(f"Failed to sync frameworks to DB: {e}")
            try:
                self.db.rollback()
            except Exception:
                pass

    # --------------------------------------------------------
    # Framework Queries
    # --------------------------------------------------------

    def get_frameworks(self) -> List[Dict[str, Any]]:
        """List all available compliance frameworks."""
        result = []
        for fw in self._frameworks.values():
            categories: Dict[str, int] = {}
            automated_count = 0
            for ctrl in fw.controls:
                categories[ctrl.category] = categories.get(ctrl.category, 0) + 1
                if ctrl.automated_check:
                    automated_count += 1
            result.append({
                "framework_id": fw.framework_id,
                "name": fw.name,
                "version": fw.version,
                "description": fw.description,
                "total_controls": fw.total_controls,
                "categories": categories,
                "automated_controls": automated_count,
                "manual_controls": fw.total_controls - automated_count,
            })
        return result

    def get_framework(self, framework_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific framework with all controls."""
        fw = self._frameworks.get(framework_id)
        if not fw:
            return None

        controls_by_category: Dict[str, List[Dict]] = {}
        for ctrl in fw.controls:
            cat = ctrl.category
            if cat not in controls_by_category:
                controls_by_category[cat] = []
            controls_by_category[cat].append({
                "control_id": ctrl.control_id,
                "control_number": ctrl.control_number,
                "title": ctrl.title,
                "description": ctrl.description,
                "requirement_text": ctrl.requirement_text,
                "evidence_types": ctrl.evidence_types,
                "automated_check": ctrl.automated_check,
            })

        return {
            "framework_id": fw.framework_id,
            "name": fw.name,
            "version": fw.version,
            "description": fw.description,
            "total_controls": fw.total_controls,
            "controls_by_category": controls_by_category,
        }

    # --------------------------------------------------------
    # Assessment Lifecycle
    # --------------------------------------------------------

    def start_assessment(self, client_id: str, framework_id: str, assessed_by: str = "") -> Optional[Dict[str, Any]]:
        """Start a new compliance assessment for a client."""
        fw = self._frameworks.get(framework_id)
        if not fw:
            return None

        assessment_id = f"ca-{uuid.uuid4().hex[:12]}"
        control_statuses = {ctrl.control_id: ControlStatus.NOT_ASSESSED for ctrl in fw.controls}

        assessment = ComplianceAssessment(
            assessment_id=assessment_id,
            client_id=client_id,
            framework_id=framework_id,
            assessed_by=assessed_by,
            controls_not_assessed=fw.total_controls,
            control_statuses=control_statuses,
        )
        self._assessments[assessment_id] = assessment

        # Persist to DB
        if self._use_db:
            try:
                orm_a = AssessmentORM(
                    assessment_id=assessment_id,
                    client_id=client_id,
                    framework_id=framework_id,
                    assessed_by=assessed_by,
                    started_at=assessment.started_at,
                    overall_score=0.0,
                    controls_compliant=0,
                    controls_non_compliant=0,
                    controls_partial=0,
                    controls_na=0,
                    controls_not_assessed=fw.total_controls,
                    control_statuses=control_statuses,
                )
                self.db.add(orm_a)
                self.db.commit()
            except Exception as e:
                logger.warning(f"Failed to persist assessment: {e}")
                try:
                    self.db.rollback()
                except Exception:
                    pass

        return self._assessment_to_dict(assessment)

    def update_control_status(
        self, assessment_id: str, control_id: str,
        status: str, notes: str = "", assessed_by: str = ""
    ) -> Optional[Dict[str, Any]]:
        """Update the status of a control within an assessment."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None
        if control_id not in assessment.control_statuses:
            return None

        assessment.control_statuses[control_id] = status
        self._recalculate_assessment(assessment)

        # Persist
        if self._use_db:
            try:
                orm_a = self.db.query(AssessmentORM).filter(
                    AssessmentORM.assessment_id == assessment_id
                ).first()
                if orm_a:
                    orm_a.control_statuses = dict(assessment.control_statuses)
                    orm_a.overall_score = assessment.overall_score
                    orm_a.controls_compliant = assessment.controls_compliant
                    orm_a.controls_non_compliant = assessment.controls_non_compliant
                    orm_a.controls_partial = assessment.controls_partial
                    orm_a.controls_na = assessment.controls_na
                    orm_a.controls_not_assessed = assessment.controls_not_assessed
                    self.db.commit()
            except Exception as e:
                logger.warning(f"Failed to update assessment in DB: {e}")
                try:
                    self.db.rollback()
                except Exception:
                    pass

        return {
            "assessment_id": assessment_id,
            "control_id": control_id,
            "status": status,
            "overall_score": assessment.overall_score,
            "controls_compliant": assessment.controls_compliant,
            "controls_non_compliant": assessment.controls_non_compliant,
            "controls_partial": assessment.controls_partial,
            "controls_na": assessment.controls_na,
            "controls_not_assessed": assessment.controls_not_assessed,
        }

    def _recalculate_assessment(self, assessment: ComplianceAssessment):
        """Recalculate assessment scores from control statuses."""
        statuses = assessment.control_statuses
        assessment.controls_compliant = sum(1 for s in statuses.values() if s == ControlStatus.COMPLIANT)
        assessment.controls_non_compliant = sum(1 for s in statuses.values() if s == ControlStatus.NON_COMPLIANT)
        assessment.controls_partial = sum(1 for s in statuses.values() if s == ControlStatus.PARTIALLY_COMPLIANT)
        assessment.controls_na = sum(1 for s in statuses.values() if s == ControlStatus.NOT_APPLICABLE)
        assessment.controls_not_assessed = sum(1 for s in statuses.values() if s == ControlStatus.NOT_ASSESSED)

        applicable = len(statuses) - assessment.controls_na
        if applicable > 0:
            weighted = assessment.controls_compliant + (assessment.controls_partial * 0.5)
            assessment.overall_score = round((weighted / applicable) * 100, 1)
        else:
            assessment.overall_score = 100.0

    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    def add_finding(
        self, assessment_id: str, control_id: str,
        severity: str, description: str, recommendation: str,
        due_date: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Add a finding to an assessment."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        finding_id = f"cf-{uuid.uuid4().hex[:12]}"
        due_dt = None
        if due_date:
            try:
                due_dt = datetime.strptime(due_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        finding = Finding(
            finding_id=finding_id,
            assessment_id=assessment_id,
            control_id=control_id,
            severity=severity,
            description=description,
            recommendation=recommendation,
            due_date=due_dt,
        )
        self._findings[finding_id] = finding
        assessment.findings.append(finding)

        # Persist
        if self._use_db:
            try:
                orm_f = FindingORM(
                    finding_id=finding_id,
                    assessment_id=assessment_id,
                    control_id=control_id,
                    severity=severity,
                    description=description,
                    recommendation=recommendation,
                    due_date=due_dt,
                    status=FindingStatus.OPEN,
                )
                self.db.add(orm_f)
                self.db.commit()
            except Exception as e:
                logger.warning(f"Failed to persist finding: {e}")
                try:
                    self.db.rollback()
                except Exception:
                    pass

        return self._finding_to_dict(finding)

    def update_finding(self, finding_id: str, status: Optional[str] = None, recommendation: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Update a finding's status or recommendation."""
        finding = self._findings.get(finding_id)
        if not finding:
            return None

        if status:
            finding.status = status
        if recommendation is not None:
            finding.recommendation = recommendation

        # Persist
        if self._use_db:
            try:
                orm_f = self.db.query(FindingORM).filter(
                    FindingORM.finding_id == finding_id
                ).first()
                if orm_f:
                    if status:
                        orm_f.status = status
                    if recommendation is not None:
                        orm_f.recommendation = recommendation
                    self.db.commit()
            except Exception as e:
                logger.warning(f"Failed to update finding in DB: {e}")
                try:
                    self.db.rollback()
                except Exception:
                    pass

        return self._finding_to_dict(finding)

    # --------------------------------------------------------
    # Reports & Dashboard
    # --------------------------------------------------------

    def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get assessment details."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None
        return self._assessment_to_dict(assessment)

    def get_assessment_report(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Generate a compliance report for an assessment."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        fw = self._frameworks.get(assessment.framework_id)
        if not fw:
            return None

        # Build control details
        control_details = []
        for ctrl in fw.controls:
            status = assessment.control_statuses.get(ctrl.control_id, ControlStatus.NOT_ASSESSED)
            related_findings = [
                self._finding_to_dict(f)
                for f in assessment.findings
                if f.control_id == ctrl.control_id
            ]
            control_details.append({
                "control_id": ctrl.control_id,
                "control_number": ctrl.control_number,
                "title": ctrl.title,
                "category": ctrl.category,
                "status": status,
                "automated_check": ctrl.automated_check,
                "findings": related_findings,
            })

        # Category breakdown
        category_scores: Dict[str, Dict] = {}
        for ctrl in fw.controls:
            cat = ctrl.category
            if cat not in category_scores:
                category_scores[cat] = {"total": 0, "compliant": 0, "non_compliant": 0, "partial": 0, "na": 0, "not_assessed": 0}
            category_scores[cat]["total"] += 1
            s = assessment.control_statuses.get(ctrl.control_id, ControlStatus.NOT_ASSESSED)
            if s == ControlStatus.COMPLIANT:
                category_scores[cat]["compliant"] += 1
            elif s == ControlStatus.NON_COMPLIANT:
                category_scores[cat]["non_compliant"] += 1
            elif s == ControlStatus.PARTIALLY_COMPLIANT:
                category_scores[cat]["partial"] += 1
            elif s == ControlStatus.NOT_APPLICABLE:
                category_scores[cat]["na"] += 1
            else:
                category_scores[cat]["not_assessed"] += 1

        # Calculate category scores
        for cat, counts in category_scores.items():
            applicable = counts["total"] - counts["na"]
            if applicable > 0:
                weighted = counts["compliant"] + (counts["partial"] * 0.5)
                counts["score"] = round((weighted / applicable) * 100, 1)
            else:
                counts["score"] = 100.0

        open_findings = [self._finding_to_dict(f) for f in assessment.findings if f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)]
        critical_findings = [self._finding_to_dict(f) for f in assessment.findings if f.severity == FindingSeverity.CRITICAL]

        return {
            "assessment_id": assessment.assessment_id,
            "client_id": assessment.client_id,
            "framework": {
                "framework_id": fw.framework_id,
                "name": fw.name,
                "version": fw.version,
            },
            "assessed_by": assessment.assessed_by,
            "started_at": assessment.started_at.isoformat() + "Z",
            "completed_at": assessment.completed_at.isoformat() + "Z" if assessment.completed_at else None,
            "overall_score": assessment.overall_score,
            "summary": {
                "total_controls": fw.total_controls,
                "compliant": assessment.controls_compliant,
                "non_compliant": assessment.controls_non_compliant,
                "partially_compliant": assessment.controls_partial,
                "not_applicable": assessment.controls_na,
                "not_assessed": assessment.controls_not_assessed,
            },
            "category_scores": category_scores,
            "controls": control_details,
            "findings_summary": {
                "total": len(assessment.findings),
                "open": len(open_findings),
                "critical": len(critical_findings),
            },
            "open_findings": open_findings,
            "critical_findings": critical_findings,
        }

    def calculate_compliance_score(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Calculate and return detailed compliance scoring."""
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            return None

        self._recalculate_assessment(assessment)
        return {
            "assessment_id": assessment_id,
            "overall_score": assessment.overall_score,
            "controls_compliant": assessment.controls_compliant,
            "controls_non_compliant": assessment.controls_non_compliant,
            "controls_partial": assessment.controls_partial,
            "controls_na": assessment.controls_na,
            "controls_not_assessed": assessment.controls_not_assessed,
            "total_controls": len(assessment.control_statuses),
            "pass": assessment.overall_score >= 80.0,
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Get compliance dashboard across all assessments."""
        frameworks_summary = self.get_frameworks()
        total_assessments = len(self._assessments)
        active_assessments = [a for a in self._assessments.values() if a.completed_at is None]

        # Aggregate scores by framework
        framework_scores: Dict[str, List[float]] = {}
        client_scores: Dict[str, List[float]] = {}
        for a in self._assessments.values():
            framework_scores.setdefault(a.framework_id, []).append(a.overall_score)
            client_scores.setdefault(a.client_id, []).append(a.overall_score)

        avg_framework_scores = {
            fid: round(sum(scores) / len(scores), 1) if scores else 0
            for fid, scores in framework_scores.items()
        }

        avg_client_scores = {
            cid: round(sum(scores) / len(scores), 1) if scores else 0
            for cid, scores in client_scores.items()
        }

        total_findings = len(self._findings)
        open_findings = sum(1 for f in self._findings.values() if f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS))
        critical_open = sum(1 for f in self._findings.values() if f.severity == FindingSeverity.CRITICAL and f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS))

        # Overdue findings
        now = datetime.now(timezone.utc)
        overdue = sum(
            1 for f in self._findings.values()
            if f.due_date and f.due_date < now and f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
        )

        return {
            "available_frameworks": len(self._frameworks),
            "frameworks": frameworks_summary,
            "total_assessments": total_assessments,
            "active_assessments": len(active_assessments),
            "avg_framework_scores": avg_framework_scores,
            "avg_client_scores": avg_client_scores,
            "findings": {
                "total": total_findings,
                "open": open_findings,
                "critical_open": critical_open,
                "overdue": overdue,
            },
        }

    # --------------------------------------------------------
    # Shield Integration
    # --------------------------------------------------------

    def map_shield_events_to_controls(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Map Aither Shield security events to compliance controls.
        Returns impacted controls per event so MSPs can track
        which compliance areas are at risk.
        """
        results = []
        for event in events:
            event_type = event.get("event_type", "")
            mapped_control_ids = SHIELD_EVENT_CONTROL_MAP.get(event_type, [])

            impacted_controls = []
            for ctrl_id in mapped_control_ids:
                # Find framework and control details
                fw_id = ctrl_id.split("-")[0]
                # Map short prefix to framework_id
                prefix_map = {
                    "hipaa": "fw-hipaa",
                    "soc2": "fw-soc2",
                    "nist171": "fw-nist-171",
                    "cmmc": "fw-cmmc",
                    "pci": "fw-pci-dss",
                }
                full_fw_id = prefix_map.get(fw_id, "")
                fw = self._frameworks.get(full_fw_id)
                if fw:
                    for ctrl in fw.controls:
                        if ctrl.control_id == ctrl_id:
                            impacted_controls.append({
                                "control_id": ctrl.control_id,
                                "framework": fw.name,
                                "control_number": ctrl.control_number,
                                "title": ctrl.title,
                                "category": ctrl.category,
                            })
                            break

            results.append({
                "event_type": event_type,
                "event_id": event.get("event_id", ""),
                "timestamp": event.get("timestamp", ""),
                "impacted_controls": impacted_controls,
                "impacted_frameworks": list({c["framework"] for c in impacted_controls}),
                "total_impacted": len(impacted_controls),
            })

        return results

    # --------------------------------------------------------
    # Serializers
    # --------------------------------------------------------

    def _assessment_to_dict(self, a: ComplianceAssessment) -> Dict[str, Any]:
        fw = self._frameworks.get(a.framework_id)
        return {
            "assessment_id": a.assessment_id,
            "client_id": a.client_id,
            "framework_id": a.framework_id,
            "framework_name": fw.name if fw else "",
            "assessed_by": a.assessed_by,
            "started_at": a.started_at.isoformat() + "Z",
            "completed_at": a.completed_at.isoformat() + "Z" if a.completed_at else None,
            "overall_score": a.overall_score,
            "controls_compliant": a.controls_compliant,
            "controls_non_compliant": a.controls_non_compliant,
            "controls_partial": a.controls_partial,
            "controls_na": a.controls_na,
            "controls_not_assessed": a.controls_not_assessed,
            "total_controls": len(a.control_statuses),
            "findings_count": len(a.findings),
        }

    def _finding_to_dict(self, f: Finding) -> Dict[str, Any]:
        return {
            "finding_id": f.finding_id,
            "assessment_id": f.assessment_id,
            "control_id": f.control_id,
            "severity": f.severity,
            "description": f.description,
            "recommendation": f.recommendation,
            "due_date": f.due_date.strftime("%Y-%m-%d") if f.due_date else None,
            "status": f.status,
            "created_at": f.created_at.isoformat() + "Z",
        }
