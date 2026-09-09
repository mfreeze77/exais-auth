"""Actual temporary Git repositories exercise exact-byte checkpoint extraction."""
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from package_checkpoint import committed_files

class CommittedSnapshotTests(unittest.TestCase):
    def setUp(self):
        scratch=ROOT/'.runtime/snapshot-tests';scratch.mkdir(parents=True,exist_ok=True)
        self.temporary=tempfile.TemporaryDirectory(prefix='git-',dir=scratch)
        self.repo=Path(self.temporary.name).resolve()
        self.git('init','--quiet')

    def tearDown(self):self.temporary.cleanup()

    def git(self,*args,body=None):
        return subprocess.run(['git','-c','user.name=Snapshot test','-c','user.email=snapshot@localhost',*args],
                              input=body,cwd=self.repo,capture_output=True,check=True).stdout

    def commit(self):
        self.git('commit','--quiet','-m','Fixture');return self.git('rev-parse','HEAD').decode().strip()

    def test_nested_export_attributes_cannot_omit_or_rewrite_committed_source(self):
        files={'.gitattributes':b'* -text\n','vendor/.gitattributes':b'.gitignore export-ignore\nignored.txt export-ignore\nsubst.txt export-subst\n',
               'vendor/.gitignore':b'local-cache/\n','vendor/ignored.txt':b'required source\r\n',
               'vendor/subst.txt':b'$Format:%H$\n','vendor/binary.dat':b'\x00\xff\r\n\x00',
               'vendor/space name.txt':b'preserve bytes\n','duplicate.txt':b'preserve bytes\n'}
        for name,body in files.items():
            p=self.repo/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body)
        self.git('add','--all');commit=self.commit()
        with tarfile.open(fileobj=io.BytesIO(self.git('archive','--format=tar',commit))) as archive:
            self.assertNotIn('vendor/ignored.txt',archive.getnames())
            self.assertNotEqual(archive.extractfile('vendor/subst.txt').read(),files['vendor/subst.txt'])
        (self.repo/'vendor/ignored.txt').write_bytes(b'uncommitted drift')
        self.assertEqual(committed_files(self.repo,commit),files)

    def test_committed_symlink_is_rejected_without_reading_its_target(self):
        oid=self.git('hash-object','-w','--stdin',body=b'../../outside-secret').decode().strip()
        self.git('update-index','--add','--cacheinfo','120000',oid,'unsafe-link')
        with self.assertRaisesRegex(ValueError,'regular committed'):committed_files(self.repo,self.commit())

    def test_committed_private_paths_are_rejected(self):
        (self.repo/'.env').write_bytes(b'FIXTURE_ONLY=value\n');self.git('add','.env')
        with self.assertRaises(AssertionError):committed_files(self.repo,self.commit())

if __name__=='__main__':unittest.main(verbosity=2)
