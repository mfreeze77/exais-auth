"""Ownership guard for the explicitly adapted, locally built Core image."""
import re
import json
import subprocess

TAG='expertauth-oss-core:12.2.0-probe'
ORIGINAL='sha256:5ec6ccc3fd5dc7eff16afa48b3bf6abdd4d378077f2428cae3abf8a8bc2e30bf'

def require_atomic_core(image):
    labels=image['Config'].get('Labels') or {}
    if (not re.fullmatch('sha256:[0-9a-f]{64}',image['Id']) or
        labels.get('org.expertauth.project')!='expert-auth' or
        labels.get('org.expertauth.purpose')!='atomic-core-runtime' or
        labels.get('org.expertauth.adaptation')!='password-session-v1' or
        not re.fullmatch('[0-9a-f]{32}',labels.get('org.expertauth.build-run',''))):
        raise ValueError('Atomic Core image ownership differs')
    return labels['org.expertauth.build-run']

def current_core_image():
    image=json.loads(subprocess.check_output(['docker','image','inspect',TAG],timeout=30))[0]
    if image['Id']==ORIGINAL:
        labels=image['Config'].get('Labels') or {}
        if labels.get('org.expertauth.project')!='expert-auth' or labels.get('org.expertauth.purpose')!='runtime-notice-image':
            raise ValueError('Original notice-image ownership differs')
    else: require_atomic_core(image)
    return image['Id']
