"""Verify build-only artifacts and retain the Jakarta API's shipped license."""
import hashlib
import io
import json
import pathlib
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent
NS = {"v": "https://schema.gradle.org/dependency-verification"}
metadata = ET.parse(ROOT / "gradle/verification-metadata.xml")
components = metadata.findall(".//v:component", NS)
records = []
for component in components:
    jars = [item for item in component.findall("v:artifact", NS) if item.attrib["name"].endswith(".jar")]
    for artifact in jars:
        group, name, version = (component.attrib[key] for key in ("group", "name", "version"))
        filename = artifact.attrib["name"]
        url = "https://repo.maven.apache.org/maven2/" + group.replace(".", "/") + "/" + name + "/" + version + "/" + filename
        raw = urllib.request.urlopen(url, timeout=30).read()
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == artifact.find("v:sha256", NS).attrib["value"], "Artifact differs from strict build hash"
        with zipfile.ZipFile(io.BytesIO(raw)) as jar:
            license_names = [entry for entry in jar.namelist() if any(term in entry.upper() for term in ("LICENSE", "NOTICE", "COPYRIGHT")) and not entry.endswith("/")]
            retained = []
            if group == "jakarta.ws.rs":
                for entry in license_names:
                    destination = ROOT / "LICENSES" / ("jakarta.ws.rs-api-3.1.0-" + pathlib.PurePosixPath(entry).name)
                    destination.write_bytes(jar.read(entry))
                    retained.append({"archive_path": entry, "retained_path": str(destination.relative_to(ROOT)), "sha256": hashlib.sha256(jar.read(entry)).hexdigest()})
        records.append({"coordinate": group + ":" + name + ":" + version, "url": url, "artifact_sha256": digest, "license": "Apache-2.0" if group == "org.keycloak" else "EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0", "license_evidence": "LICENSES/keycloak-LICENSE.txt and pinned source report" if group == "org.keycloak" else retained, "scope": "compileOnly, transitive=false", "shaded_into_extension": False, "upstream_classes_modified": False})
report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python audit_build_dependencies.py", "exit_code": 0, "artifact_count": len(records), "artifacts": records, "dependency_metadata": "gradle/verification-metadata.xml also pins parent and imported BOM metadata", "license_boundary": "Original extension JAR contains no copied upstream classes or bundled dependency JARs. Pinned Keycloak runtime image and its full component-license audit are separate from this build-only report.", "input_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ("audit_build_dependencies.py", "build.gradle", "gradle.lockfile", "gradle/verification-metadata.xml")}}
(ROOT / "BUILD_DEPENDENCY_REPORT.json").write_text(json.dumps(report, indent=2) + "\n")
print("Verified " + str(len(records)) + " compile-only artifact hashes and retained Jakarta license")
