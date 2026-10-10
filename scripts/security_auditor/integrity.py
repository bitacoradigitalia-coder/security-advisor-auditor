"""Full-text integrity anchored to the original Git blob, portable across LF/CRLF."""
import hashlib

from .safeio import read_bounded

# git show 56332414226e2c36dd73cd4d22c0e35c0348c347:references/audit-methodology.md
# Full text verified against the Windows CRLF copy before introducing this value.
CANONICAL_SHA256 = '904d385ea10a960b5b0b383b99471fc3250c0f753ef63a3d5a36f86ebeed928a'


def verify_methodology(path):
    data = read_bounded(path, 100_000)
    # Only transport representation is normalized. No whitespace trimming,
    # Unicode normalization, heading extraction, or content rewriting.
    text = data.decode('utf-8-sig').replace('\r\n', '\n')
    canonical = hashlib.sha256(text.encode('utf-8')).hexdigest()
    if canonical != CANONICAL_SHA256:
        raise ValueError('Contenido de metodología distinto del original verificado')
    return {'raw_sha256': hashlib.sha256(data).hexdigest(), 'canonical_sha256': canonical,
            'normalization': 'UTF-8 sin BOM; CRLF a LF únicamente', 'verified': True}
