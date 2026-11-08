"""
Evidence Engine for Security Advisor Auditor v2.2
Recopila, normaliza y valida evidencias de vulnerabilidades.

Este módulo implementa un sistema de evidencias que garantiza que:
- Cada hallazgo tiene evidencia reproducible
- Los secretos están redactados
- Las evidencias son verificables
- Los niveles de confianza son justificados
"""

import json
import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
from pathlib import Path


class EvidenceType(Enum):
    """Tipos de evidencia."""
    REQUEST = "request"           # Solicitud HTTP
    RESPONSE = "response"         # Respuesta HTTP
    PAYLOAD = "payload"           # Payload utilizado
    ERROR = "error"               # Mensaje de error
    TIME = "time"                 # Tiempo de respuesta
    CONTENT = "content"           # Contenido (HTML, JSON, etc.)
    HEADER = "header"             # Headers HTTP
    COOKIE = "cookie"             # Cookies
    REDIRECT = "redirect"         # Redirección
    SCREENSHOT = "screenshot"     # Captura de pantalla
    LOG = "log"                   # Log de aplicación
    FILE = "file"                 # Archivo
    CODE = "code"                 # Código fuente
    CONFIG = "config"             # Configuración


class ConfidenceLevel(Enum):
    """Niveles de confianza."""
    FALSE = "false"               # Falso positivo confirmado
    LOW = "low"                   # Baja confianza (< 30%)
    MEDIUM = "medium"             # Confianza media (30-70%)
    HIGH = "high"                 # Alta confianza (70-90%)
    CONFIRMED = "confirmed"       # Confirmado (> 90%)


class VerificationStatus(Enum):
    """Estados de verificación."""
    CANDIDATE = "CANDIDATE"       # Candidato (sin verificar)
    PROBABLE = "PROBABLE"         # Probable (evidencia débil)
    CONFIRMED = "CONFIRMED"       # Confirmado (evidencia fuerte)
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Falso positivo
    NOT_VERIFIED = "NOT_VERIFIED"    # No verificado


@dataclass
class Evidence:
    """
    Evidencia de un hallazgo de vulnerabilidad.
    
    Cada evidencia debe ser:
    - Reproducible
    - Verificable
    - Con secretos redactados
    - Con contexto claro
    """
    evidence_id: str = field(default_factory=lambda: hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16])
    evidence_type: EvidenceType = EvidenceType.RESPONSE
    finding_id: Optional[str] = None
    
    # Datos de la evidencia
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    payload: Optional[str] = None
    parameter: Optional[str] = None
    location: Optional[str] = None  # Archivo:linea o URL#param
    
    # Metadatos
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""  # Origen (scanner, fuzzer, static_analysis, etc.)
    tool: str = ""  # Herramienta específica
    
    # Redacción
    is_redacted: bool = True
    redacted_fields: List[str] = field(default_factory=list)
    
    # Verificación
    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    verification_method: str = ""
    verification_notes: str = ""
    
    # Referencias
    references: List[str] = field(default_factory=list)
    cwe: Optional[int] = None
    cvss: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertir a diccionario."""
        return {
            'evidence_id': self.evidence_id,
            'evidence_type': self.evidence_type.value,
            'finding_id': self.finding_id,
            'request': self._redact_dict(self.request) if self.request else None,
            'response': self._redact_dict(self.response) if self.response else None,
            'payload': self._redact_str(self.payload) if self.payload else None,
            'parameter': self.parameter,
            'location': self.location,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'tool': self.tool,
            'is_redacted': self.is_redacted,
            'redacted_fields': self.redacted_fields,
            'verification_status': self.verification_status.value,
            'confidence': self.confidence.value,
            'verification_method': self.verification_method,
            'verification_notes': self.verification_notes,
            'references': self.references,
            'cwe': self.cwe,
            'cvss': self.cvss
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Evidence':
        """Crear desde diccionario."""
        return cls(
            evidence_id=data.get('evidence_id', ''),
            evidence_type=EvidenceType(data.get('evidence_type', 'response')),
            finding_id=data.get('finding_id'),
            request=data.get('request'),
            response=data.get('response'),
            payload=data.get('payload'),
            parameter=data.get('parameter'),
            location=data.get('location'),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else datetime.now(timezone.utc),
            source=data.get('source', ''),
            tool=data.get('tool', ''),
            is_redacted=data.get('is_redacted', True),
            redacted_fields=data.get('redacted_fields', []),
            verification_status=VerificationStatus(data.get('verification_status', 'NOT_VERIFIED')),
            confidence=ConfidenceLevel(data.get('confidence', 'LOW')),
            verification_method=data.get('verification_method', ''),
            verification_notes=data.get('verification_notes', ''),
            references=data.get('references', []),
            cwe=data.get('cwe'),
            cvss=data.get('cvss')
        )
    
    def _redact_str(self, text: Optional[str]) -> Optional[str]:
        """Redactar secretos en texto."""
        if not text or not self.is_redacted:
            return text
        
        # Patrones de secretos
        secret_patterns = [
            (r'password["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', '[REDACTED]'),
            (r'token["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', '[REDACTED]'),
            (r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', '[REDACTED]'),
            (r'secret["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', '[REDACTED]'),
            (r'auth["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', '[REDACTED]'),
            (r'session["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', '[REDACTED]'),
            (r'jwt["\']?\s*[:=]\s*["\']?([^"\'&\s]+)', '[REDACTED]'),
            (r'Bearer\s+([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)', 'Bearer [REDACTED]'),
            (r'"?access_token"?\s*[:=]\s*"?([^"\'&\s]+)', '[REDACTED]'),
        ]
        
        for pattern, replacement in secret_patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        
        return text
    
    def _redact_dict(self, data: Optional[Dict]) -> Optional[Dict]:
        """Redactar secretos en diccionario."""
        if not data or not self.is_redacted:
            return data
        
        redacted: Dict[str, Any] = {}
        sensitive_keys = {'password', 'token', 'api_key', 'apikey', 'secret', 
                         'auth', 'session', 'jwt', 'access_token', 'refresh_token',
                         'cookie', 'authorization', 'proxy-authorization'}
        
        for key, value in data.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                redacted[key] = '[REDACTED]'
                if key not in self.redacted_fields:
                    self.redacted_fields.append(key)
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            elif isinstance(value, str):
                redacted[key] = self._redact_str(value)
            else:
                redacted[key] = value
        
        return redacted


@dataclass
class Finding:
    """
    Hallazgo de vulnerabilidad con evidencias.
    
    Cada hallazgo debe incluir:
    - ID único
    - Nombre y descripción
    - Severidad
    - Confianza
    - Estado de verificación
    - Evidencias
    - Pasos de reproducción
    - Recomendación
    """
    finding_id: str = field(default_factory=lambda: hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16])
    name: str = ""
    description: str = ""
    
    # Clasificación
    severity: str = "medium"  # info, low, medium, high, critical
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    
    # Ubicación
    target: str = ""
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    method: Optional[str] = None
    location: Optional[str] = None  # file:line o URL#param
    
    # Evidencias
    evidences: List[Evidence] = field(default_factory=list)
    
    # Detalles técnicos
    vulnerability_type: Optional[str] = None  # sqli, xss, ssrf, etc.
    cwe: Optional[int] = None
    cvss: Optional[float] = None
    
    # Reproducción
    reproduction_steps: List[str] = field(default_factory=list)
    payload: Optional[str] = None
    
    # Impacto y recomendación
    impact: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadatos
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    tool: str = ""
    
    # Verificación
    verified_by: Optional[str] = None  # Usuario o sistema que verificó
    verification_date: Optional[datetime] = None
    verification_notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertir a diccionario."""
        return {
            'finding_id': self.finding_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence.value,
            'verification_status': self.verification_status.value,
            'target': self.target,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'method': self.method,
            'location': self.location,
            'evidences': [e.to_dict() for e in self.evidences],
            'vulnerability_type': self.vulnerability_type,
            'cwe': self.cwe,
            'cvss': self.cvss,
            'reproduction_steps': self.reproduction_steps,
            'payload': self.payload,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'references': self.references,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'tool': self.tool,
            'verified_by': self.verified_by,
            'verification_date': self.verification_date.isoformat() if self.verification_date else None,
            'verification_notes': self.verification_notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Crear desde diccionario."""
        finding = cls(
            finding_id=data.get('finding_id', ''),
            name=data.get('name', ''),
            description=data.get('description', ''),
            severity=data.get('severity', 'medium'),
            confidence=ConfidenceLevel(data.get('confidence', 'LOW')),
            verification_status=VerificationStatus(data.get('verification_status', 'NOT_VERIFIED')),
            target=data.get('target', ''),
            endpoint=data.get('endpoint'),
            parameter=data.get('parameter'),
            method=data.get('method'),
            location=data.get('location'),
            vulnerability_type=data.get('vulnerability_type'),
            cwe=data.get('cwe'),
            cvss=data.get('cvss'),
            reproduction_steps=data.get('reproduction_steps', []),
            payload=data.get('payload'),
            impact=data.get('impact', ''),
            recommendation=data.get('recommendation', ''),
            references=data.get('references', []),
            source=data.get('source', ''),
            tool=data.get('tool', ''),
            verified_by=data.get('verified_by'),
            verification_notes=data.get('verification_notes', '')
        )
        
        if data.get('timestamp'):
            finding.timestamp = datetime.fromisoformat(data['timestamp'])
        
        if data.get('verification_date'):
            finding.verification_date = datetime.fromisoformat(data['verification_date'])
        
        finding.evidences = [Evidence.from_dict(e) for e in data.get('evidences', [])]
        
        return finding
    
    def add_evidence(self, evidence: Evidence) -> None:
        """Añadir evidencia."""
        evidence.finding_id = self.finding_id
        self.evidences.append(evidence)
    
    def get_confidence_score(self) -> float:
        """Calcular puntuación de confianza (0-100)."""
        confidence_scores = {
            ConfidenceLevel.FALSE: 0,
            ConfidenceLevel.LOW: 25,
            ConfidenceLevel.MEDIUM: 50,
            ConfidenceLevel.HIGH: 75,
            ConfidenceLevel.CONFIRMED: 100
        }
        return confidence_scores.get(self.confidence, 0)
    
    def is_reproducible(self) -> bool:
        """Verificar si el hallazgo es reproducible."""
        return len(self.reproduction_steps) > 0 and len(self.evidences) > 0


class EvidenceEngine:
    """
    Motor de evidencias para recopilar y normalizar evidencias.
    
    Funcionalidades:
    - Recopilar evidencias de múltiples fuentes
    - Normalizar formatos de evidencia
    - Redactar secretos automáticamente
    - Validar evidencias
    - Almacenar evidencias de forma estructurada
    """
    
    # Patrones para detectar vulnerabilidades
    VULNERABILITY_PATTERNS = {
        'sqli': {
            'error_patterns': [
                r'sql syntax.*error',
                r'mysql.*error',
                r'postgresql.*error',
                r'oracle.*error',
                r'syntax error.*sql',
                r'unknown column',
                r'table.*doesn[\'\"].*exist',
                r'warning: mysql',
            ],
            'reflection_patterns': [
                r'\'.*OR.*\'',
                r'\'.*UNION.*SELECT',
            ],
            'time_patterns': []  # Detectar por tiempo de respuesta
        },
        'xss': {
            'error_patterns': [],
            'reflection_patterns': [
                r'<script>.*</script>',
                r'onerror=.*',
                r'onload=.*',
                r'alert\(.*\)',
                r'document\.cookie',
            ],
            'time_patterns': []
        },
        'ssrf': {
            'error_patterns': [
                r'connection refused',
                r'connection timed out',
                r'could not resolve',
            ],
            'reflection_patterns': [],
            'time_patterns': []
        },
        'rce': {
            'error_patterns': [
                r'command not found',
                r'syntax error',
            ],
            'reflection_patterns': [
                r'root:x:',
                r'uid=0',
            ],
            'time_patterns': []
        },
        'lfi': {
            'error_patterns': [
                r'file.*not found',
                r'no such file',
            ],
            'reflection_patterns': [
                r'root:x:',
                r'/etc/passwd',
                r'/etc/shadow',
            ],
            'time_patterns': []
        }
    }
    
    # Secretos a redactar
    SECRET_PATTERNS = [
        r'password["\']?\s*[:=]\s*["\']?[^"\'&\s]+',
        r'token["\']?\s*[:=]\s*["\']?[^"\'&\s]+',
        r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\'&\s]+',
        r'secret["\']?\s*[:=]\s*["\']?[^"\'&\s]+',
        r'auth["\']?\s*[:=]\s*["\']?[^"\'&\s]+',
        r'session["\']?\s*[:=]\s*["\']?[^"\'&\s]+',
        r'jwt["\']?\s*[:=]\s*["\']?[^"\'&\s]+',
        r'Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    ]
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Inicializar EvidenceEngine.
        
        Args:
            storage_path: Ruta para almacenar evidencias (opcional)
        """
        self.storage_path = storage_path
        self._findings: Dict[str, Finding] = {}
        self._evidences: Dict[str, Evidence] = {}
    
    def create_finding(
        self,
        name: str,
        description: str,
        severity: str = "medium",
        vulnerability_type: Optional[str] = None,
        target: str = "",
        **kwargs
    ) -> Finding:
        """
        Crear un nuevo hallazgo.
        
        Args:
            name: Nombre del hallazgo
            description: Descripción
            severity: Severidad (info, low, medium, high, critical)
            vulnerability_type: Tipo de vulnerabilidad
            target: Objetivo (URL o archivo)
            **kwargs: Argumentos adicionales
        
        Returns:
            Finding: Hallazgo creado
        """
        finding = Finding(
            name=name,
            description=description,
            severity=severity,
            vulnerability_type=vulnerability_type,
            target=target,
            **kwargs
        )
        
        self._findings[finding.finding_id] = finding
        
        if self.storage_path:
            self._save_finding(finding)
        
        return finding
    
    def add_evidence(
        self,
        finding_id: str,
        evidence_type: EvidenceType,
        **kwargs
    ) -> Optional[Evidence]:
        """
        Añadir evidencia a un hallazgo.
        
        Args:
            finding_id: ID del hallazgo
            evidence_type: Tipo de evidencia
            **kwargs: Argumentos de la evidencia
        
        Returns:
            Evidence: Evidencia creada o None si no se encontró el hallazgo
        """
        finding = self._findings.get(finding_id)
        if not finding:
            return None
        
        evidence = Evidence(
            evidence_type=evidence_type,
            **kwargs
        )
        
        finding.add_evidence(evidence)
        self._evidences[evidence.evidence_id] = evidence
        
        if self.storage_path:
            self._save_finding(finding)
        
        return evidence
    
    def create_evidence_from_request_response(
        self,
        finding_id: str,
        request: Dict[str, Any],
        response: Dict[str, Any],
        vulnerability_type: Optional[str] = None,
        parameter: Optional[str] = None
    ) -> Optional[Evidence]:
        """
        Crear evidencia a partir de una petición y respuesta HTTP.
        
        Args:
            finding_id: ID del hallazgo
            request: Diccionario con la petición
            response: Diccionario con la respuesta
            vulnerability_type: Tipo de vulnerabilidad detectada
            parameter: Parámetro afectado
        
        Returns:
            Evidence: Evidencia creada
        """
        evidence = Evidence(
            evidence_type=EvidenceType.RESPONSE,
            request=request,
            response=response,
            parameter=parameter,
            source='http_request'
        )
        
        # Detectar tipo de vulnerabilidad si no se especifica
        if vulnerability_type:
            evidence.verification_method = f'detection:{vulnerability_type}'
        else:
            # Intentar detectar automáticamente
            detected_type = self._detect_vulnerability_type(response)
            if detected_type:
                evidence.verification_method = f'auto_detection:{detected_type}'
        
        # Añadir a hallazgo
        finding = self._findings.get(finding_id)
        if finding:
            finding.add_evidence(evidence)
            self._evidences[evidence.evidence_id] = evidence
            
            if self.storage_path:
                self._save_finding(finding)
        
        return evidence
    
    def _detect_vulnerability_type(self, response: Dict[str, Any]) -> Optional[str]:
        """
        Detectar tipo de vulnerabilidad a partir de la respuesta.
        
        Args:
            response: Diccionario con la respuesta HTTP
        
        Returns:
            str: Tipo de vulnerabilidad o None
        """
        if not response:
            return None
        
        content = response.get('text', '') or response.get('content', '')
        status_code = response.get('status_code', 0)
        headers = response.get('headers', {})
        
        # SQL Injection
        for pattern in self.VULNERABILITY_PATTERNS['sqli']['error_patterns']:
            if re.search(pattern, content, re.IGNORECASE):
                return 'sqli'
        
        # XSS
        for pattern in self.VULNERABILITY_PATTERNS['xss']['reflection_patterns']:
            if re.search(pattern, content, re.IGNORECASE):
                return 'xss'
        
        # Path Disclosure
        if re.search(r'/var/www/|/home/|/usr/local/|C:\\inetpub\\', content):
            return 'path_disclosure'
        
        # Debug Information
        if re.search(r'phpinfo\(\)|var_dump|print_r|stack trace|at\s+\w+\.\w+\(|debug=true', content, re.IGNORECASE):
            return 'debug_information'
        
        return None
    
    def set_verification_status(
        self,
        finding_id: str,
        status: VerificationStatus,
        confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
        verified_by: Optional[str] = None,
        notes: str = ""
    ) -> bool:
        """
        Establecer estado de verificación de un hallazgo.
        
        Args:
            finding_id: ID del hallazgo
            status: Estado de verificación
            confidence: Nivel de confianza
            verified_by: Quien verificó
            notes: Notas de verificación
        
        Returns:
            bool: True si se actualizó correctamente
        """
        finding = self._findings.get(finding_id)
        if not finding:
            return False
        
        finding.verification_status = status
        finding.confidence = confidence
        finding.verified_by = verified_by
        finding.verification_date = datetime.now(timezone.utc)
        finding.verification_notes = notes
        
        if self.storage_path:
            self._save_finding(finding)
        
        return True
    
    def verify_finding(self, finding_id: str, verification_data: Dict[str, Any]) -> bool:
        """
        Verificar un hallazgo con datos adicionales.
        
        Args:
            finding_id: ID del hallazgo
            verification_data: Datos de verificación
        
        Returns:
            bool: True si se verificó correctamente
        """
        finding = self._findings.get(finding_id)
        if not finding:
            return False
        
        # Aplicar reglas de verificación
        new_status, new_confidence = self._apply_verification_rules(finding, verification_data)
        
        return self.set_verification_status(
            finding_id=finding_id,
            status=new_status,
            confidence=new_confidence,
            verified_by=verification_data.get('verified_by', 'automatic'),
            notes=verification_data.get('notes', '')
        )
    
    def _apply_verification_rules(
        self,
        finding: Finding,
        verification_data: Dict[str, Any]
    ) -> Tuple[VerificationStatus, ConfidenceLevel]:
        """
        Aplicar reglas de verificación para determinar el nuevo estado.
        
        Args:
            finding: Hallazgo a verificar
            verification_data: Datos de verificación
        
        Returns:
            Tuple: (nuevo estado, nuevo nivel de confianza)
        """
        # Regla 1: Si hay evidencia de control positiva y negativa
        if verification_data.get('has_positive_control') and verification_data.get('has_negative_control'):
            return VerificationStatus.CONFIRMED, ConfidenceLevel.HIGH
        
        # Regla 2: Si hay evidencia reproducible
        if finding.is_reproducible() and len(finding.evidences) >= 2:
            return VerificationStatus.PROBABLE, ConfidenceLevel.MEDIUM
        
        # Regla 3: Si hay solo una evidencia
        if len(finding.evidences) == 1:
            return VerificationStatus.CANDIDATE, ConfidenceLevel.LOW
        
        # Regla 4: Si es un falso positivo confirmado
        if verification_data.get('is_false_positive'):
            return VerificationStatus.FALSE_POSITIVE, ConfidenceLevel.FALSE
        
        # Regla 5: Por defecto
        return finding.verification_status, finding.confidence
    
    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Obtener un hallazgo por ID."""
        return self._findings.get(finding_id)
    
    def get_all_findings(self) -> List[Finding]:
        """Obtener todos los hallazgos."""
        return list(self._findings.values())
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Obtener hallazgos por severidad."""
        return [f for f in self._findings.values() if f.severity == severity]
    
    def get_findings_by_type(self, vulnerability_type: str) -> List[Finding]:
        """Obtener hallazgos por tipo de vulnerabilidad."""
        return [f for f in self._findings.values() if f.vulnerability_type == vulnerability_type]
    
    def get_findings_by_status(self, status: VerificationStatus) -> List[Finding]:
        """Obtener hallazgos por estado de verificación."""
        return [f for f in self._findings.values() if f.verification_status == status]
    
    def clear(self) -> None:
        """Limpiar todos los hallazgos y evidencias."""
        self._findings.clear()
        self._evidences.clear()
    
    def _save_finding(self, finding: Finding) -> None:
        """Guardar un hallazgo en almacenamiento."""
        if not self.storage_path:
            return
        
        try:
            Path(self.storage_path).parent.mkdir(parents=True, exist_ok=True)
            
            if Path(self.storage_path).exists():
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                data = {'findings': [], 'evidences': []}
            
            # Actualizar hallazgo
            finding_dict = finding.to_dict()
            existing_index = next((i for i, f in enumerate(data['findings']) 
                                  if f.get('finding_id') == finding.finding_id), None)
            
            if existing_index is not None:
                data['findings'][existing_index] = finding_dict
            else:
                data['findings'].append(finding_dict)
            
            # Guardar evidencias
            for evidence in finding.evidences:
                evidence_dict = evidence.to_dict()
                existing_evidence_index = next((i for i, e in enumerate(data['evidences']) 
                                               if e.get('evidence_id') == evidence.evidence_id), None)
                if existing_evidence_index is None:
                    data['evidences'].append(evidence_dict)
            
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            # Log error but continue
            pass
    
    def load_from_storage(self) -> None:
        """Cargar hallazgos desde almacenamiento."""
        if not self.storage_path or not Path(self.storage_path).exists():
            return
        
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for finding_data in data.get('findings', []):
                finding = Finding.from_dict(finding_data)
                self._findings[finding.finding_id] = finding
                
                for evidence_data in data.get('evidences', []):
                    if evidence_data.get('finding_id') == finding.finding_id:
                        evidence = Evidence.from_dict(evidence_data)
                        finding.add_evidence(evidence)
                        self._evidences[evidence.evidence_id] = evidence
        except Exception as e:
            # Log error but continue
            pass
