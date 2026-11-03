"""
Example: Using Evidence Engine and Verification Engine

This example demonstrates how to use the new evidence and verification
components in Security Advisor Auditor v2.2.
"""

from scripts.core.evidence_engine import (
    EvidenceEngine, Evidence, EvidenceType, 
    Finding, ConfidenceLevel, VerificationStatus
)
from scripts.core.verification_engine import VerificationEngine


def main():
    print("=" * 60)
    print("EVIDENCE ENGINE & VERIFICATION ENGINE EXAMPLE")
    print("=" * 60)
    
    # 1. Create Evidence Engine
    print("\n1. Creating Evidence Engine...")
    evidence_engine = EvidenceEngine()
    print("   ✅ Evidence Engine created")
    
    # 2. Create a Finding
    print("\n2. Creating a Finding...")
    finding = evidence_engine.create_finding(
        name="SQL Injection Candidate",
        description="Potential SQL injection vulnerability detected in login endpoint",
        severity="high",
        vulnerability_type="sqli",
        target="https://example.com/login"
    )
    print(f"   ✅ Finding created: {finding.finding_id}")
    print(f"   - Name: {finding.name}")
    print(f"   - Severity: {finding.severity}")
    print(f"   - Status: {finding.verification_status.value}")
    print(f"   - Confidence: {finding.confidence.value}")
    
    # 3. Add Evidence
    print("\n3. Adding Evidence...")
    
    # Simulated request and response
    request_data = {
        'method': 'POST',
        'url': 'https://example.com/login',
        'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
        'data': {'username': 'admin\' OR \'1\'=\'1', 'password': 'test'}
    }
    
    response_data = {
        'status_code': 500,
        'headers': {'Server': 'Apache'},
        'text': "SQL syntax error near 'OR '1'='1'"
    }
    
    evidence = evidence_engine.add_evidence(
        finding_id=finding.finding_id,
        evidence_type=EvidenceType.RESPONSE,
        request=request_data,
        response=response_data,
        parameter='username'
    )
    print(f"   ✅ Evidence added: {evidence.evidence_id}")
    print(f"   - Type: {evidence.evidence_type.value}")
    print(f"   - Parameter: {evidence.parameter}")
    
    # 4. Create Verification Engine
    print("\n4. Creating Verification Engine...")
    verification_engine = VerificationEngine(evidence_engine)
    print("   ✅ Verification Engine created")
    
    # 5. Verify Finding
    print("\n5. Verifying Finding...")
    result = verification_engine.run_automatic_verification(finding)
    print(f"   - Original Status: {result['original_status']}")
    print(f"   - New Status: {result['new_status']}")
    print(f"   - Original Confidence: {result['original_confidence']}")
    print(f"   - New Confidence: {result['new_confidence']}")
    print(f"   - Changed: {result['changed']}")
    print(f"   - Rules Applied: {result['rules_applied']}")
    
    # 6. Check Updated Finding
    print("\n6. Updated Finding Status...")
    updated_finding = evidence_engine.get_finding(finding.finding_id)
    if updated_finding:
        print(f"   - Status: {updated_finding.verification_status.value}")
        print(f"   - Confidence: {updated_finding.confidence.value}")
        print(f"   - Evidences: {len(updated_finding.evidences)}")
    
    # 7. Add Control Test Evidence
    print("\n7. Adding Control Test Evidence...")
    
    # Positive control: Same payload causes SQL error
    positive_request = {
        'method': 'POST',
        'url': 'https://example.com/login',
        'data': {'username': 'admin\' OR \'1\'=\'1', 'password': 'test'}
    }
    positive_response = {
        'status_code': 500,
        'text': "SQL syntax error"
    }
    
    # Negative control: Normal request works
    negative_request = {
        'method': 'POST',
        'url': 'https://example.com/login',
        'data': {'username': 'admin', 'password': 'test'}
    }
    negative_response = {
        'status_code': 200,
        'text': "Login successful"
    }
    
    # Add control evidences
    evidence_engine.add_evidence(
        finding_id=finding.finding_id,
        evidence_type=EvidenceType.REQUEST,
        request=positive_request,
        response=positive_response,
        verification_method='control_test:positive'
    )
    
    evidence_engine.add_evidence(
        finding_id=finding.finding_id,
        evidence_type=EvidenceType.REQUEST,
        request=negative_request,
        response=negative_response,
        verification_method='control_test:negative'
    )
    
    print("   ✅ Control test evidences added")
    
    # 8. Re-verify with new evidence
    print("\n8. Re-verifying with Control Tests...")
    result = verification_engine.run_automatic_verification(finding)
    print(f"   - New Status: {result['new_status']}")
    print(f"   - New Confidence: {result['new_confidence']}")
    print(f"   - Changed: {result['changed']}")
    
    # 9. Get Suggested Actions
    print("\n9. Suggested Verification Actions...")
    actions = verification_engine.suggest_verification_actions(finding)
    for action in actions:
        print(f"   - {action}")
    
    # 10. Check for False Positives
    print("\n10. Checking for False Positive Candidates...")
    fp_candidates = verification_engine.get_false_positive_candidates()
    print(f"   - Candidates: {len(fp_candidates)}")
    
    # 11. Manual Verification
    print("\n11. Manual Verification...")
    evidence_engine.set_verification_status(
        finding_id=finding.finding_id,
        status=VerificationStatus.CONFIRMED,
        confidence=ConfidenceLevel.HIGH,
        verified_by='security_analyst',
        notes='Confirmed via control tests and error analysis'
    )
    
    updated_finding = evidence_engine.get_finding(finding.finding_id)
    if updated_finding:
        print(f"   ✅ Manually verified")
        print(f"   - Status: {updated_finding.verification_status.value}")
        print(f"   - Confidence: {updated_finding.confidence.value}")
        print(f"   - Verified by: {updated_finding.verified_by}")
    
    # 12. Export Finding
    print("\n12. Exporting Finding...")
    finding_dict = finding.to_dict()
    print(f"   ✅ Finding exported to dict with {len(finding_dict)} fields")
    
    print("\n" + "=" * 60)
    print("EXAMPLE COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == '__main__':
    main()
