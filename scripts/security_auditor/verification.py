"""Evidence-gated state changes. Validation checks structure, not reviewer truth."""
STATES = {'CANDIDATE', 'PROBABLE', 'CONFIRMED', 'FALSE_POSITIVE', 'NOT_VERIFIED'}
ALLOWED = {
    'CANDIDATE': {'PROBABLE', 'FALSE_POSITIVE', 'NOT_VERIFIED'},
    'PROBABLE': {'CONFIRMED', 'FALSE_POSITIVE', 'NOT_VERIFIED'},
    'NOT_VERIFIED': {'PROBABLE', 'FALSE_POSITIVE'},
    'FALSE_POSITIVE': {'CANDIDATE'},
    'CONFIRMED': {'CANDIDATE'},
}


def validate_state(finding):
    state = finding.get('status')
    if state not in STATES: raise ValueError('Estado de hallazgo inválido')
    v = finding['verification']; e = finding['evidence']
    history = v.get('state_history', [])
    previous = 'CANDIDATE'
    for step in history:
        if step.get('from') != previous or step.get('to') not in ALLOWED[previous] or not step.get('reason'):
            raise ValueError('Transición sin motivo o secuencia inválida')
        previous = step['to']
    if previous != state: raise ValueError('Estado sin transición registrada')
    if state == 'PROBABLE' and not (e.get('source') and e.get('trace') or e.get('context')):
        raise ValueError('Probabilidad requiere evidencia contextual')
    if state == 'FALSE_POSITIVE' and not e.get('mitigation'):
        raise ValueError('Falso positivo requiere evidencia de mitigación')
    if state == 'NOT_VERIFIED' and not v.get('limitations'):
        raise ValueError('No verificado requiere motivo')
    if state == 'CONFIRMED' and not all(v.get(k) for k in
            ('reviewer', 'reachability', 'control_violation', 'reproduction')):
        raise ValueError('Confirmación requiere evidencia reproducible revisada')
    if v.get('exploitation', 'not_tested') not in ('not_tested', 'confirmed'):
        raise ValueError('Explotación inválida')
    if v.get('exploitation') == 'confirmed' and (state != 'CONFIRMED' or
            v.get('status') != 'local_test' or v.get('executed') is not True or
            not all(v.get(k) for k in ('test_result', 'authorization', 'isolation'))):
        raise ValueError('Explotación requiere prueba ejecutada, autorización y aislamiento')


def transition(finding, state, reason):
    old = finding.get('status', 'CANDIDATE')
    if old not in STATES or state not in ALLOWED[old] or not isinstance(reason, str) or not reason.strip():
        raise ValueError('Transición no permitida o motivo ausente')
    import copy
    proposed = copy.deepcopy(finding)
    proposed['status'] = state
    proposed['verification'].setdefault('state_history', []).append({'from': old, 'to': state, 'reason': reason})
    if state == 'CONFIRMED' and proposed['verification']['status'] == 'not_verified':
        proposed['verification']['status'] = 'static_trace'
    validate_state(proposed)
    proposed['type'] = ('confirmed_vulnerability' if state == 'CONFIRMED' else
                        'informational' if state == 'FALSE_POSITIVE' else 'probable_weakness')
    if state == 'FALSE_POSITIVE':
        proposed.update(severity='informational', priority='no_action')
    finding.clear(); finding.update(proposed)
    return finding


def enrich_candidate(finding, category=None, analyzer='legacy-static'):
    finding.update(status='CANDIDATE', category=category or finding['cwe'], analyzer=analyzer,
                   regression_test='Probar entradas seguras y peligrosas en aislamiento autorizado')
    finding['verification'].update(exploitation='not_tested', state_history=[],
                                   method='syntax-only', limitations=['Contexto no resuelto'])
    return finding
