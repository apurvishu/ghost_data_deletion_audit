"""Build the ZIP and verify that its extracted runtime reproduces root output.csv."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import zipfile

from package import package


def main():
    root=Path(__file__).resolve().parents[1]
    if not (root/'output.csv').is_file():raise ValueError('Generate output.csv first')
    package()
    build=root/'build';build.mkdir(exist_ok=True)
    target=Path(tempfile.mkdtemp(prefix='submission-replay-',dir=build)).resolve()
    assert target.is_relative_to(build.resolve())
    with zipfile.ZipFile(root/'code.zip') as archive:
        for member in archive.namelist():
            if not (target/member).resolve().is_relative_to(target):raise ValueError('Archive path escapes replay directory')
        archive.extractall(target)
    # The extracted runtime has no local .deps, cache, or dataset directory.
    result=subprocess.run([sys.executable,str(target/'code/main.py'),'--dataset',str(root/'dataset'),'--output',str(target/'output.csv')],cwd=target,text=True,capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stdout+'\n'+result.stderr)
    expected=(root/'output.csv').read_bytes();actual=(target/'output.csv').read_bytes()
    if expected!=actual:raise AssertionError('Packaged runtime output differs from root output.csv')
    print(result.stdout.strip())
    print('PASS: ZIP output is byte-for-byte identical; SHA-256 '+hashlib.sha256(actual).hexdigest())
    print('Replay artifacts: '+str(target))


if __name__=='__main__':main()
