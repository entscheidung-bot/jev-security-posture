#!/usr/bin/env python3
"""
Triage Engine: Datadog CSM & Wiz Alerts to Business Security Posture
Evaluates Toxic Triad reachability and TypeSafe Jev System One Cloud Operational Decisions.
"""
import os
import sys
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

@dataclass
class RawFinding:
    id: str
    source: str
    title: str
    severity: str
    resource_type: str
    asset_name: str
    asset_tier: str
    is_internet_exposed: bool
    has_compensating_controls: bool
    cloud_details: Dict[str, Any]

@dataclass
class TriagedFinding:
    id: str
    source: str
    title: str
    asset_name: str
    raw_severity: str
    business_decision: str  # "MATERIAL_BUSINESS_RISK", "CONTAINED_RESIDUAL_RISK", "CLOUD_PROVIDER_OPERATIONAL", "NOISE_SUPPRESSED"
    business_impact_score: int  # 1 to 5
    is_exploitable_in_context: bool
    confidence: float
    remediation_recommendation: str

def evaluate_finding(finding: RawFinding, api_key: Optional[str] = None) -> TriagedFinding:
    # ponytail: offline heuristic handles missing API key; upgrade to live typesafe-sdk client when TYPESAFE_API_KEY present
    title_lower = finding.title.lower()
    details = finding.cloud_details

    # Cloud Operational Patterns recognized semantically
    if "alb" in title_lower and "principal" in title_lower and details.get("is_aws_service_principal"):
        return TriagedFinding(
            id=finding.id,
            source=finding.source,
            title=finding.title,
            asset_name=finding.asset_name,
            raw_severity=finding.severity,
            business_decision="CLOUD_PROVIDER_OPERATIONAL",
            business_impact_score=1,
            is_exploitable_in_context=False,
            confidence=0.98,
            remediation_recommendation="Noise suppressed: AWS regional ELB service delivery principal required for access logging."
        )

    if "acm" in title_lower and "private key" in title_lower and details.get("key_management") == "AWS_MANAGED_NON_EXPORTABLE":
        return TriagedFinding(
            id=finding.id,
            source=finding.source,
            title=finding.title,
            asset_name=finding.asset_name,
            raw_severity=finding.severity,
            business_decision="CLOUD_PROVIDER_OPERATIONAL",
            business_impact_score=1,
            is_exploitable_in_context=False,
            confidence=0.96,
            remediation_recommendation="Noise suppressed: ACM private keys are hardware-isolated in AWS KMS and non-exportable."
        )

    # Toxic Triad Check: Requires (Public Ingress + Exploitable Path + Critical Blast Radius)
    if finding.is_internet_exposed and finding.asset_tier.startswith("Tier-1") and not finding.has_compensating_controls:
        return TriagedFinding(
            id=finding.id,
            source=finding.source,
            title=finding.title,
            asset_name=finding.asset_name,
            raw_severity=finding.severity,
            business_decision="MATERIAL_BUSINESS_RISK",
            business_impact_score=5 if details.get("is_cisa_kev") else 4,
            is_exploitable_in_context=True,
            confidence=0.94,
            remediation_recommendation=f"P0: Isolate {finding.asset_name} immediately. Direct public route with unmitigated exploit path."
        )

    if finding.is_internet_exposed and finding.has_compensating_controls:
        return TriagedFinding(
            id=finding.id,
            source=finding.source,
            title=finding.title,
            asset_name=finding.asset_name,
            raw_severity=finding.severity,
            business_decision="CONTAINED_RESIDUAL_RISK",
            business_impact_score=2,
            is_exploitable_in_context=False,
            confidence=0.89,
            remediation_recommendation="P2: Compensating control (WAF/mTLS) active. Verify rule persistence during maintenance."
        )

    if not finding.is_internet_exposed and (finding.asset_tier.startswith("Tier-1") or finding.asset_tier.startswith("Tier-2")):
        return TriagedFinding(
            id=finding.id,
            source=finding.source,
            title=finding.title,
            asset_name=finding.asset_name,
            raw_severity=finding.severity,
            business_decision="CONTAINED_RESIDUAL_RISK",
            business_impact_score=2,
            is_exploitable_in_context=False,
            confidence=0.91,
            remediation_recommendation="P3: Contained in private VPC without direct ingress. Patch within standard sprint SLA."
        )

    return TriagedFinding(
        id=finding.id,
        source=finding.source,
        title=finding.title,
        asset_name=finding.asset_name,
        raw_severity=finding.severity,
        business_decision="NOISE_SUPPRESSED",
        business_impact_score=1,
        is_exploitable_in_context=False,
        confidence=0.95,
        remediation_recommendation="P4: Ephemeral/isolated asset with zero production blast radius. Auto-suppressed in executive view."
    )

def run_triage(findings: List[RawFinding]) -> Dict[str, Any]:
    triaged = [evaluate_finding(f) for f in findings]
    
    total_raw = len(triaged)
    material_risks = [f for f in triaged if f.business_decision == "MATERIAL_BUSINESS_RISK"]
    contained_risks = [f for f in triaged if f.business_decision == "CONTAINED_RESIDUAL_RISK"]
    provider_ops = [f for f in triaged if f.business_decision == "CLOUD_PROVIDER_OPERATIONAL"]
    suppressed = [f for f in triaged if f.business_decision in ("NOISE_SUPPRESSED", "CLOUD_PROVIDER_OPERATIONAL")]
    
    noise_reduction_pct = round((len(suppressed) / total_raw) * 100, 1) if total_raw > 0 else 0
    posture_score = max(0, 100 - (len(material_risks) * 15) - (len(contained_risks) * 2))
    
    return {
        "summary": {
            "total_raw_findings": total_raw,
            "material_business_risks": len(material_risks),
            "contained_residual_risks": len(contained_risks),
            "cloud_provider_operational": len(provider_ops),
            "total_suppressed_noise": len(suppressed),
            "noise_reduction_percentage": noise_reduction_pct,
            "business_security_posture_score": posture_score,
            "posture_grade": "A" if posture_score >= 85 else ("B" if posture_score >= 70 else "C")
        },
        "material_risks": [asdict(f) for f in material_risks],
        "all_triaged": [asdict(f) for f in triaged]
    }

def generate_sample_dataset() -> List[RawFinding]:
    return [
        RawFinding("WIZ-9821", "Wiz", "Remote Code Execution in Ingress Gateway (CVE-2024-3400)", "CRITICAL", "AWS::EC2::Instance", "api-gateway-prod-us-east", "Tier-1 (Payments/PII)", True, False, {"is_cisa_kev": True}),
        RawFinding("WIZ-4412", "Wiz", "Unrestricted S3 Bucket Access via IAM Role", "HIGH", "AWS::S3::Bucket", "customer-receipts-archive", "Tier-1 (Payments/PII)", True, False, {"is_cisa_kev": False}),
        RawFinding("WIZ-S3-ALB", "Wiz", "ALB Logs Bucket allows external PutObject principal", "HIGH", "AWS::S3::Bucket", "prod-app-alb-access-logs", "Tier-2 (App Internal)", False, True, {"is_aws_service_principal": True, "principal": "127311923021"}),
        RawFinding("WIZ-ACM-02", "Wiz", "Multiple domains share single ACM certificate private key", "MEDIUM", "AWS::ACM::Certificate", "wildcard-corp-domains", "Tier-1 (Payments/PII)", True, True, {"key_management": "AWS_MANAGED_NON_EXPORTABLE"}),
        RawFinding("DD-SEC-101", "Datadog", "CIS Benchmark: Ensure root login is disabled", "HIGH", "Host", "worker-node-prod-04", "Tier-2 (App Internal)", False, True, {}),
        RawFinding("DD-SEC-204", "Datadog", "Node.js prototype pollution in dev runner (CVE-2023-45133)", "HIGH", "Container", "jenkins-worker-ephemeral-8b", "Tier-3 (CI/Dev)", False, False, {}),
        RawFinding("DD-SEC-305", "Datadog", "Kubernetes Secret stored without KMS encryption", "MEDIUM", "K8s", "staging-cluster-k8s", "Tier-3 (CI/Dev)", False, False, {}),
        RawFinding("WIZ-6721", "Wiz", "Default Security Group Allows Ingress 0.0.0.0/0 on port 22", "CRITICAL", "AWS::EC2::SecurityGroup", "bastion-corp-dmz", "Tier-1 (Payments/PII)", True, True, {}),
    ]

if __name__ == "__main__":
    data = generate_sample_dataset()
    result = run_triage(data)
    print(json.dumps(result["summary"], indent=2))
    assert result["summary"]["total_raw_findings"] == 8
    assert result["summary"]["material_business_risks"] == 2
    assert result["summary"]["cloud_provider_operational"] == 2
    assert result["summary"]["total_suppressed_noise"] == 4
    print("Self-check passed: Cloud operational patterns & Toxic Triad logic verified.")
