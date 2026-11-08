"""
Verification Engine for Security Advisor Auditor v2.2
Valida y verifica hallazgos de vulnerabilidades.

Este módulo implementa:
- Reglas de transición entre estados (CANDIDATE -> PROBABLE -> CONFIRMED)
- Pruebas de control positivas y negativas
- Reducción de falsos positivos
- Cálculo de confianza basado en evidencias
"""

import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from enum import Enum

from .evidence_engine import (
    Finding, Evidence, EvidenceType, 
    VerificationStatus, ConfidenceLevel, EvidenceEngine
)


class VerificationMethod(Enum):
    """Métodos de verificación."""
    MANUAL = "manual"                 # Verificación manual
    AUTOMATIC = "automatic"           # Verificación automática
    CONTROL_TEST = "control_test"     # Prueba de control
    REPRODUCTION = "reproduction"     # Reproducción
    CORRELATION = "correlation"       # Correlación con otros hallazgos
    EXTERNAL = "external"             # Verificación externa (CVE, etc.)


@dataclass
class VerificationRule:
    """
    Regla para transición entre estados de verificación.
    
    Define:
    - Condiciones para transitar de un estado a otro
    - Requisitos de evidencia
    - Nivel de confianza mínimo
    """
    rule_id: str = field(default_factory=lambda: hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:8])
    name: str = ""
    description: str = ""
    
    # Estados
    from_status: VerificationStatus = VerificationStatus.CANDIDATE
    to_status: VerificationStatus = VerificationStatus.PROBABLE
    
    # Condiciones
    min_evidences: int = 1
    min_confidence: ConfidenceLevel = ConfidenceLevel.LOW
    required_evidence_types: Set[EvidenceType] = field(default_factory=set)
    
    # Verificación
    verification_method: VerificationMethod = VerificationMethod.AUTOMATIC
    verification_function: Optional[Callable] = None
    
    # Vul
nerabilidades específicas
    applicable_types: Set[str] = field(default_factory=set)  # Ej: {'sqli', 'xss'}
    
    def can_apply(self, finding: Finding) -> bool:
        """Verificar si esta regla se puede aplicar a un hallazgo."""
        if finding.verification_status != self.from_status:
            return False
        
        if self.applicable_types and finding.vulnerability_type not in self.applicable_types:
            return False
        
        if len(finding.evidences) < self.min_evidences:
            return False
        
        if finding.confidence.value < self.min_confidence.value:
            return False
        
        if self.required_evidence_types:
            evidence_types = {e.evidence_type for e in finding.evidences}
            if not self.required_evidence_types.issubset(evidence_types):
                return False
        
        return True
    
    def apply(self, finding: Finding) -> Tuple[VerificationStatus, ConfidenceLevel]:
        """
        Aplicar la regla a un hallazgo.
        
        Returns:
            Tuple: (nuevo estado, nuevo nivel de confianza)
        """
        if not self.can_apply(finding):
            return finding.verification_status, finding.confidence
        
        # Ejecutar función de verificación si existe
        if self.verification_function:
            result = self.verification_function(finding)
            if result is False:
                return finding.verification_status, finding.confidence
        
        return self.to_status, self._calculate_confidence(finding)
    
    def _calculate_confidence(self, finding: Finding) -> ConfidenceLevel:
        """Calcular nivel de confianza después de aplicar la regla."""
        # Si la regla especifica un mínimo, usar ese
        if self.min_confidence.value > finding.confidence.value:
            return self.min_confidence
        return finding.confidence


class VerificationEngine:
    """
    Motor de verificación para validar hallazg
os.
    
    Funcionalidades:
    - Definir reglas de verificación
    - Aplicar reglas automáticamente
    - Verificar hallazgos manualmente
    - Reducir falsos positivos
    - Calcular confianza
    """
    
    def __init__(self, evidence_engine: Optional[EvidenceEngine] = None) -> None:
        """
        Inicializar VerificationEngine.
        
        Args:
            evidence_engine: Motor de evidencias asociado
        """
        self.evidence_engine = evidence_engine
        self._rules: Dict[str, VerificationRule] = {}
        self._register_default_rules()
    
    def _register_default_rules(self) -> None:
        """Registrar reglas de verificación por defecto."""
        
        # Regla 1: CANDIDATE -> PROBABLE (con 1 evidencia)
        self.add_rule(VerificationRule(
            name="candidate_to_probable_with_evidence",
            description="Transición de CANDIDATE a PROBABLE con al menos 1 evidencia",
            from_status=VerificationStatus.CANDIDATE,
            to_status=VerificationStatus.PROBABLE,
            min_evidences=1,
            min_confidence=ConfidenceLevel.LOW,
            verification_method=VerificationMethod.AUTOMATIC
        ))
        
        # Regla 2: PROBABLE -> CONFIRMED (con 2+ evidencias y control test)
        self.add_rule(VerificationRule(
            name="probable_to_confirmed_with_controls",
            description="Transición de PROBABLE a CONFIRMED con pruebas de control",
            from_status=VerificationStatus.PROBABLE,
            to_status=VerificationStatus.CONFIRMED,
            min_evidences=2,
            min_confidence=ConfidenceLevel.MEDIUM,
            required_evidence_types={EvidenceType.REQUEST, EvidenceType.RESPONSE},
            verification_method=VerificationMethod.CONTROL_TEST,
            verification_function=self._verify_with_controls
        ))
        
        # Regla 3: CANDIDATE -> FALSE_POSITIVE (error genérico 500 solo)
        self.add_rule(VerificationRule(
            name="ca
ndidate_to_false_positive_generic_error",
            description="Transición a FALSE_POSITIVE si solo hay error 500 genérico",
            from_status=VerificationStatus.CANDIDATE,
            to_status=VerificationStatus.FALSE_POSITIVE,
            min_evidences=1,
            applicable_types={'sqli', 'xss', 'rce', 'lfi'},
            verification_method=VerificationMethod.AUTOMATIC,
            verification_function=self._verify_not_generic_error
        ))
        
        # Regla 4: PROBABLE -> CONFIRMED (SQLi con error de base de datos)
        self.add_rule(VerificationRule(
            name="probable_to_confirmed_sqli_error",
            description="Transición a CONFIRMED para SQLi con error de BD",
            from_status=VerificationStatus.PROBABLE,
            to_status=VerificationStatus.CONFIRMED,
            min_evidences=1,
            applicable_types={'sqli'},
            verification_method=VerificationMethod.AUTOMATIC,
            verification_function=self._verify_sqli_error
        ))
        
        # Regla 5: PROBABLE -> CONFIRMED (XSS con reflexión de payload)
        self.add_rule(VerificationRule(
            name="probable_to_confirmed_xss_reflection",
            description="Transición a CONFIRMED para XSS con reflexión",
            from_status=VerificationStatus.PROBABLE,
            to_status=VerificationStatus.CONFIRMED,
            min_evidences=1,
            applicable_types={'xss'},
            verification_method=VerificationMethod.AUTOMATIC,
            verification_function=self._verify_xss_reflection
        ))
        
        # Regla 6: CANDIDATE -> CONFIRMED (evidencia fuerte)
        self.add_rule(VerificationRule(
            name="candidate_to_confirmed_strong_evidence",
            description="Transición directa a CONFIRMED con evidencia fuerte",
            from_status=VerificationStatus.CANDIDATE,
            to_status=VerificationStatus.CONFIRMED,
            min_evidences=2,
            min_confidence=Confidenc
eLevel.HIGH,
            verification_method=VerificationMethod.AUTOMATIC
        ))
    
    def add_rule(self, rule: VerificationRule) -> None:
        """Añadir una regla de verificación."""
        self._rules[rule.rule_id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Eliminar una regla de verificación."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False
    
    def get_rules(self) -> List[VerificationRule]:
        """Obtener todas las reglas."""
        return list(self._rules.values())
    
    def get_applicable_rules(self, finding: Finding) -> List[VerificationRule]:
        """Obtener reglas aplicables a un hallazgo."""
        return [rule for rule in self._rules.values() if rule.can_apply(finding)]
    
    def verify_finding(self, finding: Finding) -> Tuple[VerificationStatus, ConfidenceLevel]:
        """
        Verificar un hallazgo aplicando todas las reglas aplicables.
        
        Args:
            finding: Hallazgo a verificar
        
        Returns:
            Tuple: (nuevo estado, nuevo nivel de confianza)
        """
        current_status = finding.verification_status
        current_confidence = finding.confidence
        
        # Aplicar reglas en orden
        for rule in self._rules.values():
            if rule.can_apply(finding):
                new_status, new_confidence = rule.apply(finding)
                
                # Si el estado cambió, actualizar
                if new_status != current_status or new_confidence != current_confidence:
                    current_status = new_status
                    current_confidence = new_confidence
                    
                    # Si llegamos a CONFIRMED o FALSE_POSITIVE, parar
                    if current_status in [VerificationStatus.CONFIRMED, VerificationStatus.FALSE_POSITIVE]:
                        break
        
        return current_status, current_confidence
  
  
    def verify_all_findings(self) -> Dict[str, Tuple[VerificationStatus, ConfidenceLevel]]:
        """
        Verificar todos los hallazgos.
        
        Returns:
            Dict: {finding_id: (nuevo_status, nueva_confianza)}
        """
        if not self.evidence_engine:
            return {}
        
        results = {}
        for finding in self.evidence_engine.get_all_findings():
            new_status, new_confidence = self.verify_finding(finding)
            results[finding.finding_id] = (new_status, new_confidence)
            
            # Actualizar el hallazgo
            self.evidence_engine.set_verification_status(
                finding.finding_id,
                new_status,
                new_confidence
            )
        
        return results
    
    def manual_verify(
        self,
        finding_id: str,
        status: VerificationStatus,
        confidence: ConfidenceLevel,
        verified_by: str,
        notes: str = ""
    ) -> bool:
        """
        Verificación manual de un hallazgo.
        
        Args:
            finding_id: ID del hallazgo
            status: Nuevo estado
            confidence: Nuevo nivel de confianza
            verified_by: Quien verificó
            notes: Notas
        
        Returns:
            bool: True si se actualizó
        """
        if not self.evidence_engine:
            return False
        
        return self.evidence_engine.set_verification_status(
            finding_id=finding_id,
            status=status,
            confidence=confidence,
            verified_by=verified_by,
            notes=notes
        )
    
    # Funciones de verificación específicas
    
    def _verify_with_controls(self, finding: Finding) -> bool:
        """
        Verificar con pruebas de control positivas y negativas.
        
        Una prueba de control:
        - Positiva: Confirma que la vulnerabilidad existe
        - Negativa: Confirma que el sistema se comporta normalmente si
n el payload
        """
        # Buscar evidencia de control positiva y negativa
        has_positive = False
        has_negative = False
        
        for evidence in finding.evidences:
            if 'control_type' in evidence.__dict__:
                if evidence.__dict__['control_type'] == 'positive':
                    has_positive = True
                elif evidence.__dict__['control_type'] == 'negative':
                    has_negative = True
        
        return has_positive and has_negative
    
    def _verify_not_generic_error(self, finding: Finding) -> bool:
        """
        Verificar que NO es solo un error genérico (500, timeout, etc.).
        
        Si es solo un error genérico, debe ser marcado como FALSE_POSITIVE.
        """
        # Si solo hay una evidencia y es un error 500 genérico
        if len(finding.evidences) == 1:
            evidence = finding.evidences[0]
            response = evidence.response or {}
            status_code = response.get('status_code', 0)
            content = response.get('text', '') or response.get('content', '')
            
            # Error 500 genérico
            if status_code == 500:
                generic_errors = [
                    'internal server error',
                    '500 error',
                    'server error',
                    'error 500'
                ]
                
                content_lower = content.lower()
                for error in generic_errors:
                    if error in content_lower and not any(
                        pattern in content_lower 
                        for pattern in ['sql', 'syntax error', 'mysql', 'postgresql']
                    ):
                        return False  # NO pasa la verificación -> FALSE_POSITIVE
        
        return True  # Pasa la verificación
    
    def _verify_sqli_error(self, finding: Finding) -> bool:
        """
        Verificar que hay evidencia de error de SQL Injection.
        """
     
   sqli_patterns = [
            r'sql syntax.*error',
            r'mysql.*error',
            r'postgresql.*error',
            r'oracle.*error',
            r'syntax error.*sql',
            r'unknown column',
            r'table.*doesn[\'\"].*exist',
            r'warning: mysql',
        ]
        
        for evidence in finding.evidences:
            content = (evidence.response or {}).get('text', '') or \
                      (evidence.response or {}).get('content', '') or \
                      evidence.payload or ''
            
            for pattern in sqli_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        
        return False
    
    def _verify_xss_reflection(self, finding: Finding) -> bool:
        """
        Verificar que hay reflexión de payload (XSS confirmado).
        """
        if finding.payload:
            payload_pattern = re.escape(finding.payload)
            
            for evidence in finding.evidences:
                content = (evidence.response or {}).get('text', '') or \
                          (evidence.response or {}).get('content', '')
                
                # Buscar el payload reflejado
                if re.search(payload_pattern, content):
                    return True
        
        return False
    
    # Funciones para pruebas de control
    
    def create_control_test(
        self,
        finding: Finding,
        control_type: str,
        request: Dict[str, Any],
        response: Dict[str, Any]
    ) -> Evidence:
        """
        Crear una prueba de control para un hallazgo.
        
        Args:
            finding: Hallazgo
            control_type: 'positive' o 'negative'
            request: Petición de control
            response: Respuesta de control
        
        Returns:
            Evidence: Evidencia de control
        """
        evidence = Evidence(
            evidence_type=EvidenceType.REQUEST,
            requ
est=request,
            response=response,
            verification_method=f'control_test:{control_type}'
        )
        
        # Añadir metadato de tipo de control
        evidence.__dict__['control_type'] = control_type
        
        if self.evidence_engine:
            self.evidence_engine.add_evidence(
                finding.finding_id,
                evidence.evidence_type,
                request=request,
                response=response,
                verification_method=evidence.verification_method
            )
        
        return evidence
    
    def run_automatic_verification(self, finding: Finding) -> Dict[str, Any]:
        """
        Ejecutar verificación automática completa de un hallazgo.
        
        Args:
            finding: Hallazgo a verificar
        
        Returns:
            Dict: Resultados de la verificación
        """
        # Guardar estado original
        original_status = finding.verification_status
        original_confidence = finding.confidence
        
        # Aplicar reglas de verificación
        new_status, new_confidence = self.verify_finding(finding)
        
        # Actualizar si cambió
        if new_status != original_status or new_confidence != original_confidence:
            if self.evidence_engine:
                self.evidence_engine.set_verification_status(
                    finding.finding_id,
                    new_status,
                    new_confidence,
                    verified_by='automatic_verification'
                )
        
        return {
            'finding_id': finding.finding_id,
            'original_status': original_status.value,
            'original_confidence': original_confidence.value,
            'new_status': new_status.value,
            'new_confidence': new_confidence.value,
            'changed': new_status != original_status or new_confidence != original_confidence,
            'rules_applied': [rule.name for rule in self.get_applicable_rules(
finding)]
        }
    
    def get_false_positive_candidates(self) -> List[Finding]:
        """
        Obtener hallazgos que podrían ser falsos positivos.
        
        Returns:
            List: Hallazgos candidatos a falsos positivos
        """
        if not self.evidence_engine:
            return []
        
        candidates = []
        for finding in self.evidence_engine.get_all_findings():
            # Criterios para falso positivo:
            # 1. Solo tiene 1 evidencia
            # 2. La evidencia es un error genérico (500, timeout)
            # 3. No tiene payload específico
            if len(finding.evidences) == 1:
                evidence = finding.evidences[0]
                response = evidence.response or {}
                status_code = response.get('status_code', 0)
                content = response.get('text', '') or response.get('content', '')
                
                # Error genérico
                if status_code in [500, 502, 503, 504, 408]:
                    generic_indicators = [
                        'internal server error',
                        'bad gateway',
                        'service unavailable',
                        'gateway timeout',
                        'request timeout'
                    ]
                    
                    content_lower = content.lower()
                    if any(indicator in content_lower for indicator in generic_indicators):
                        candidates.append(finding)
        
        return candidates
    
    def suggest_verification_actions(self, finding: Finding) -> List[str]:
        """
        Sugerir acciones de verificación para un hallazgo.
        
        Args:
            finding: Hallazgo
        
        Returns:
            List: Acciones sugeridas
        """
        actions = []
        
        # Si es CANDIDATE
        if finding.verification_status == VerificationStatus.CANDIDATE:
            actions.append("🔍 Añadir más evidencias p
ara pasar a PROBABLE")
            actions.append("🎯 Realizar prueba de control positiva")
            actions.append("🎯 Realizar prueba de control negativa")
        
        # Si es PROBABLE
        elif finding.verification_status == VerificationStatus.PROBABLE:
            actions.append("✅ Realizar prueba de control positiva y negativa para confirmar")
            actions.append("🔬 Verificar manualmente el hallazgo")
            actions.append("📊 Correlacionar con otros hallazgos")
        
        # Si es CONFIRMED
        elif finding.verification_status == VerificationStatus.CONFIRMED:
            actions.append("🎯 Priorizar la corrección")
            actions.append("📋 Documentar en el informe")
        
        # Si tiene baja confianza
        if finding.confidence == ConfidenceLevel.LOW:
            actions.append("🔍 Recolectar más evidencias")
            actions.append("🎯 Verificar con pruebas de control")
        
        # Si es de tipo específico
        if finding.vulnerability_type == 'sqli':
            actions.append("🔬 Probar con diferentes payloads de SQLi")
            actions.append("🎯 Verificar si el error de BD es real")
        
        elif finding.vulnerability_type == 'xss':
            actions.append("🔬 Probar con diferentes payloads XSS")
            actions.append("🎯 Verificar si el payload se refleja en el HTML")
        
        return actions
