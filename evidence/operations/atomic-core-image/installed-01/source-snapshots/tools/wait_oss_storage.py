"""Private lab readiness: authenticate and perform a real storage query."""
import json
import os
import sys
import time
import urllib.request

url = sys.argv[1]
assert url in ('http://core-a:3567','http://core-b:3567')
for attempt in range(40):
    try:
        request = urllib.request.Request(url+'/users/count', headers={'api-key':os.environ['EXPERTAUTH_CORE_API_KEY'],'cdi-version':'5.3'})
        with urllib.request.urlopen(request,timeout=2) as response:
            body = json.load(response)
            assert response.status==200 and body['status']=='OK' and isinstance(body['count'],int)
        print(json.dumps({'storage_ready':url,'authenticated_query':True}))
        break
    except Exception:
        if attempt==39:
            raise SystemExit('Private authenticated storage readiness failed')
        time.sleep(1)
