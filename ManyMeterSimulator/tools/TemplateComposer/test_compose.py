from pathlib import Path
import hashlib
import tempfile
import unittest
import xml.etree.ElementTree as ET
from compose import compose


class ComposerTests(unittest.TestCase):
    templates = Path(__file__).resolve().parents[2] / 'ManyMeterSimulator/Templates'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.base = self.templates / 'SA1231166HP_values.xml'
        self.donor = self.templates / 'SA1231166HP_values_bill.xml'

    def run_merge(self, donor=None, output=None):
        return compose(self.base, [donor or self.donor], output or self.folder / 'master.xml', self.folder / 'report.json')

    def altered_donor(self, mutate):
        tree = ET.parse(self.donor)
        mutate(tree.getroot())
        path = self.folder / 'donor.xml'; tree.write(path)
        return path

    def test_real_d1_merge_preserves_model_and_billing(self):
        before = hashlib.sha256(self.base.read_bytes()).hexdigest()
        report = self.run_merge()
        self.assertTrue(report['model_unchanged'])
        self.assertEqual([{'logical_name': '1.0.98.1.0.255', 'source': self.donor.name, 'rows': 13}], report['imported_profiles'])
        self.assertEqual(before, hashlib.sha256(self.base.read_bytes()).hexdigest())

    def test_other_category_rejected(self):
        with self.assertRaisesRegex(ValueError, 'category mismatch'):
            self.run_merge(self.templates / 'Template-31-D2.xml')

    def test_changed_capture_rejected(self):
        def mutate(root):
            profile = next(o for o in root if o.findtext('LN') == '1.0.98.1.0.255')
            profile.find('CaptureObjects')[0].find('Attribute').text = '3'
        with self.assertRaisesRegex(ValueError, 'Capture layout mismatch'):
            self.run_merge(self.altered_donor(mutate))

    def test_changed_scaler_rejected(self):
        def mutate(root):
            next(o for o in root if o.findtext('LN') == '1.0.1.8.0.255').find('Scaler').text = '0.001'
        with self.assertRaisesRegex(ValueError, 'scaler/unit mismatch'):
            self.run_merge(self.altered_donor(mutate))

    def test_malformed_row_rejected(self):
        def mutate(root):
            row = next(o for o in root if o.findtext('LN') == '1.0.98.1.0.255').find('Buffer')[0]
            row.remove(row[-1])
        with self.assertRaisesRegex(ValueError, 'Row width'):
            self.run_merge(self.altered_donor(mutate))

    def test_source_overwrite_rejected(self):
        with self.assertRaisesRegex(ValueError, 'overwrite source'):
            self.run_merge(output=self.base)

    def test_unselected_profile_cannot_replace_existing_data_or_model(self):
        def mutate(root):
            profile = next(o for o in root if o.findtext('LN') == '1.0.99.1.0.255')
            profile.find('CaptureObjects')[0].find('Attribute').text = '99'
            profile.find('Buffer')[0].remove(profile.find('Buffer')[0][-1])
        report = self.run_merge(self.altered_donor(mutate))
        self.assertTrue(report['model_unchanged'])
        actual = ET.parse(self.folder / 'master.xml').getroot()
        original = ET.parse(self.base).getroot()
        block = lambda root: next(o for o in root if o.findtext('LN') == '1.0.99.1.0.255')
        from compose import canonical
        self.assertEqual(canonical(block(original).find('Buffer')), canonical(block(actual).find('Buffer')))

    def test_explicit_replacement_preserves_model_and_checks_compatibility(self):
        ln = '1.0.99.2.0.255'
        report = compose(self.base, [self.donor], self.folder / 'master.xml', self.folder / 'report.json', [ln])
        self.assertTrue(report['model_unchanged'])
        self.assertEqual([ln], report['explicitly_replaced_profiles'])
        def mutate(root):
            next(o for o in root if o.findtext('LN') == ln).find('CaptureObjects')[0].find('Attribute').text = '3'
        with self.assertRaisesRegex(ValueError, 'Capture layout mismatch'):
            compose(self.base, [self.altered_donor(mutate)], self.folder / 'bad.xml', self.folder / 'bad.json', [ln])
        self.assertFalse((self.folder / 'bad.xml').exists())

    def test_ambiguous_or_missing_replacement_rejected(self):
        for donors, selected, message in [([self.donor, self.donor], ['1.0.99.2.0.255'], 'Ambiguous'),
                                            ([self.donor], ['0.0.99.98.0.255'], 'no populated donor'),
                                            ([self.donor], ['9.9.9.9.9.9'], 'existing profile')]:
            with self.assertRaisesRegex(ValueError, message):
                compose(self.base, donors, self.folder / 'bad.xml', self.folder / 'bad.json', selected)
            self.assertFalse((self.folder / 'bad.xml').exists())


if __name__ == '__main__':
    unittest.main()
