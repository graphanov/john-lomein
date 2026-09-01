from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/'scripts'
sys.path.insert(0,str(SCRIPTS))

from stage_profile_distribution import PLACEHOLDER_RE, stage

class ProfileDistributionStagingTest(unittest.TestCase):
    def test_stages_rendered_installable_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime=Path(tmp)
            profile='john-lomein-guide'
            profile_dir=runtime/'profiles'/profile
            profile_dir.mkdir(parents=True)
            (profile_dir/'SOUL.md').write_text('John Lomein rendered identity\n',encoding='utf-8')
            target=stage(ROOT,runtime,profile,profile)
            soul=(target/'SOUL.md').read_text(encoding='utf-8')
            self.assertIsNone(PLACEHOLDER_RE.search(soul))
            self.assertIn('John Lomein',soul)
            self.assertTrue((target/'distribution.yaml').is_file())

    def test_rejects_any_unresolved_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime=Path(tmp)
            profile=runtime/'profiles'/'john-lomein-guide'
            profile.mkdir(parents=True)
            (profile/'SOUL.md').write_text('{{TARGET_REPO}}\n',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'contains placeholders'):
                stage(ROOT,runtime,'john-lomein-guide','john-lomein-guide')

    def test_rejects_unsafe_distribution_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime=Path(tmp)/'runtime'
            runtime.mkdir()
            profile=runtime/'profiles'/'john-lomein-guide'
            profile.mkdir(parents=True)
            (profile/'SOUL.md').write_text('rendered\n',encoding='utf-8')
            (runtime/'distributions').symlink_to(Path(tmp)/'outside')
            with self.assertRaisesRegex(ValueError,'symlink'):
                stage(ROOT,runtime,'john-lomein-guide','john-lomein-guide')

if __name__=='__main__':
    unittest.main()
