"""Python-side reader for sources.json, the Apps Script source manifest.

The mirror of scripts/sources.js, for the Python consumers: the pattern parser
in tests/test_spam_detector.py, scripts/validate.py and scripts/prod_health.py.

concat_source() must agree byte-for-byte with sources.js concatSource(). Apps
Script concatenates every .gs file into one global scope before running
anything, and the Python harness parses that concatenation as a single body of
source; if the two loaders disagreed about content or order, the JS/Python
parity check in Phase 7 would be comparing two different programs.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(ROOT, 'sources.json')


def manifest():
    """Parse and validate sources.json.

    Validated rather than trusted: a manifest that silently read as empty would
    make every consumer "succeed" against no source at all — the parser would
    find no patterns and the version checks would have nothing to disagree with.

    :raises RuntimeError: if the manifest is missing, malformed or incoherent.
    """
    try:
        with open(MANIFEST_PATH, encoding='utf-8') as fh:
            m = json.load(fh)
    except FileNotFoundError:
        raise RuntimeError('Cannot find the source manifest at %s' % MANIFEST_PATH)
    except json.JSONDecodeError as e:
        raise RuntimeError('sources.json is not valid JSON — %s' % e)

    sources = m.get('sources')
    if not isinstance(sources, list) or not sources:
        raise RuntimeError('sources.json: "sources" must be a non-empty array')
    if not all(isinstance(s, str) and s for s in sources):
        raise RuntimeError('sources.json: every entry in "sources" must be a filename')
    if len(set(sources)) != len(sources):
        dupes = sorted({s for s in sources if sources.count(s) > 1})
        raise RuntimeError('sources.json: duplicate entries in "sources": %s — '
                           'a file listed twice is concatenated twice, which is a '
                           'duplicate-declaration SyntaxError at load time'
                           % ', '.join(dupes))
    bad = [s for s in sources if s.startswith('/') or '..' in s.split('/')]
    if bad:
        raise RuntimeError('sources.json: entries must be repo-relative paths '
                           'without "..": %s' % ', '.join(bad))

    version_file = m.get('versionFile')
    if not isinstance(version_file, str) or not version_file:
        raise RuntimeError('sources.json: "versionFile" must be a non-empty string')
    if version_file not in sources:
        raise RuntimeError('sources.json: versionFile %r is not listed in "sources"'
                           % version_file)

    root = m.get('rootDir')
    if not isinstance(root, str) or not root:
        raise RuntimeError('sources.json: "rootDir" must be a non-empty string')
    # Everything clasp deploys must live under rootDir — clasp only crawls that
    # directory, so a source outside it is simply never pushed.
    outside = [s for s in sources if not s.startswith(root + '/')]
    if outside:
        raise RuntimeError('sources.json: these are not under rootDir %r, so '
                           'clasp would never push them: %s'
                           % (root, ', '.join(outside)))
    return m


def source_names():
    """Manifest-ordered source filenames, repo-relative."""
    return list(manifest()['sources'])


def source_paths():
    """Manifest-ordered absolute paths."""
    return [os.path.join(ROOT, f) for f in manifest()['sources']]


def version_file_path():
    """Absolute path of the file carrying the version markers."""
    return os.path.join(ROOT, manifest()['versionFile'])


def root_dir():
    """clasp's rootDir, repo-relative."""
    return manifest()['rootDir']


def clasp_relative(name):
    """A source's path as .claspignore sees it: relative to rootDir."""
    return os.path.relpath(name, root_dir()).replace(os.sep, '/')


def concat_source():
    """The deployed script as Apps Script will see it: all files, in order.

    Joined with NOTHING, deliberately: concatenating the split files must
    reproduce the pre-split SpamDetector.gs byte for byte, which is the proof
    that the split moved code and changed none. Any separator breaks that.

    Safe because every source file must end with a newline —
    tests/test_patch_version.js asserts it.
    """
    parts = []
    for path in source_paths():
        try:
            # newline='' disables universal-newline translation. Without it
            # Python silently rewrites CRLF to LF while Node's readFileSync does
            # not, so the two readers would emit different bytes for the same
            # file and the byte-for-byte contract above would be quietly false.
            # test_patch_version.js asserts the sources are LF-only, so this
            # reads through unchanged in practice; it is here so that if that
            # ever stops being true, the parity test fails loudly instead of the
            # difference being papered over.
            with open(path, encoding='utf-8', newline='') as fh:
                body = fh.read()
        except OSError as e:
            raise RuntimeError('sources.json lists %s, which cannot be read — %s'
                               % (os.path.relpath(path, ROOT), e))
        # Enforced HERE, not only in a test — see the note in sources.js.
        if body and not body.endswith('\n'):
            raise RuntimeError(
                '%s does not end with a newline. concat_source() joins with no '
                "separator, so this would weld its last line onto the next "
                'file\'s first.' % os.path.relpath(path, ROOT))
        parts.append(body)
    return ''.join(parts)
