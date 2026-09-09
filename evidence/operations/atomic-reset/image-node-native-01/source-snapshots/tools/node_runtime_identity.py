"""Identify the task's current Node image, including its recorded legacy image.

The original image predates project labels. Only its exact recorded digest is
accepted under that exception; new candidate images require explicit ownership.
"""
import hashlib
import json
from pathlib import Path
import re

TAG='expertauth-node-react:0.0.5'
LEGACY='sha256:a0cf7009def4f1fb626e67c2e43103dbc6d654fc2697aab28a4390868d869eaf'
ROOT=Path(__file__).resolve().parents[1]
PROOF='evidence/operations/hygiene/verification-20260909T050303Z.json'
PROOF_SHA256='faf6c986c2c8961d03f0af913ed3e2246683c9dc68fd54763de903783f2f016d'

def require_owned_node(image):
    labels=image['Config'].get('Labels') or {}
    if (labels.get('org.expertauth.project')=='expert-auth' and labels.get('org.expertauth.purpose')=='node-foundation'
            and re.fullmatch('[0-9a-f]{32}',labels.get('org.expertauth.build-run',''))):
        return 'project-and-component-labels'
    body=(ROOT/PROOF).read_bytes()
    if hashlib.sha256(body).hexdigest()!=PROOF_SHA256:
        raise ValueError('Legacy Node ownership evidence changed')
    rows=json.loads(body)['images']
    if image['Id']!=LEGACY or labels or not any(row['id']==LEGACY and row['tag']==TAG for row in rows):
        raise ValueError('Node image has neither current ownership labels nor exact recorded legacy identity')
    return 'exact-legacy-image-and-hashed-ownership-record'
