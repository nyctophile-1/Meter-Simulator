"""Merge compatible profile data while retaining the base XML's object model."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import xml.etree.ElementTree as ET


def canonical(element):
    return (element.tag, tuple(sorted(element.attrib.items())), (element.text or '').strip(),
            tuple(canonical(child) for child in element))


def index(root):
    result = {}
    for obj in root:
        ln = obj.findtext('LN')
        if not ln or ln in result:
            raise ValueError(f'Missing or duplicate logical name: {ln}')
        result[ln] = obj
    return result


def category(objects):
    return tuple(objects[ln].findtext('Value') for ln in ('0.0.94.91.9.255', '0.0.94.91.11.255'))


def model(root):
    snapshot = copy.deepcopy(root)
    for obj in snapshot:
        if obj.tag == 'GXDLMSProfileGeneric':
            for tag in ('Buffer', 'EntriesInUse'):
                child = obj.find(tag)
                if child is not None:
                    obj.remove(child)
    return canonical(snapshot)


def validate_profile(profile):
    rows, captures = profile.find('Buffer'), profile.find('CaptureObjects')
    if rows is None or captures is None:
        raise ValueError(f'Incomplete profile {profile.findtext("LN")}')
    if any(len(row) != len(captures) for row in rows):
        raise ValueError(f'Row width does not match captures: {profile.findtext("LN")}')
    if len(rows) > int(profile.findtext('ProfileEntries', '0')):
        raise ValueError(f'Rows exceed profile capacity: {profile.findtext("LN")}')


def compatible(target, donor, base_objects, donor_objects):
    if target.tag != donor.tag or target.findtext('Version', '0') != donor.findtext('Version', '0'):
        raise ValueError('Profile class/version mismatch')
    if canonical(target.find('CaptureObjects')) != canonical(donor.find('CaptureObjects')):
        raise ValueError(f'Capture layout mismatch: {target.findtext("LN")}')
    for capture in target.find('CaptureObjects'):
        ln = capture.findtext('LN')
        a, b = base_objects.get(ln), donor_objects.get(ln)
        if (a is None) != (b is None):
            raise ValueError(f'Capture object definition missing: {ln}')
        if a is not None:
            signature = lambda obj: (obj.tag, obj.findtext('Version', '0'), obj.findtext('Scaler'), obj.findtext('Unit'))
            if signature(a) != signature(b):
                raise ValueError(f'Capture class/scaler/unit mismatch: {ln}')


def compose(base_path, donor_paths, output_path, report_path, replace_profiles=()):
    paths = [Path(base_path).resolve(), *[Path(p).resolve() for p in donor_paths]]
    output_path, report_path = Path(output_path).resolve(), Path(report_path).resolve()
    if output_path in paths or report_path in paths or output_path == report_path:
        raise ValueError('Outputs must not overwrite source XMLs')
    tree = ET.parse(paths[0]); root = tree.getroot(); objects = index(root)
    original_model = model(root)
    selected_category = category(objects)
    if not all(selected_category):
        raise ValueError('Base requires explicit meter type and category')
    replacements = []
    requested = set(replace_profiles)
    replaced = set()
    if any(ln not in objects or objects[ln].tag != 'GXDLMSProfileGeneric' for ln in requested):
        raise ValueError('Replacement must name an existing profile')
    for path in paths[1:]:
        donor_objects = index(ET.parse(path).getroot())
        if category(donor_objects) != selected_category:
            raise ValueError(f'Meter type/category mismatch: {path.name}')
        for ln, target in objects.items():
            if target.tag != 'GXDLMSProfileGeneric' or ln not in donor_objects:
                continue
            donor = donor_objects[ln]
            if (len(target.find('Buffer')) != 0 and ln not in requested) or donor.find('Buffer') is None or len(donor.find('Buffer')) == 0:
                continue
            if ln in replaced:
                raise ValueError(f'Ambiguous replacement donors: {ln}')
            compatible(target, donor, objects, donor_objects)
            validate_profile(donor)
            if (len(target.find('Buffer')) == 0 or ln in requested) and len(donor.find('Buffer')) > 0:
                old_buffer = target.find('Buffer')
                position = list(target).index(old_buffer)
                target.remove(old_buffer)
                target.insert(position, copy.deepcopy(donor.find('Buffer')))
                replacements.append({'logical_name': ln, 'source': path.name, 'rows': len(donor.find('Buffer'))})
                if ln in requested:
                    replaced.add(ln)
    if requested != replaced:
        raise ValueError(f'Replacement profile has no populated donor: {sorted(requested - replaced)}')
    profiles = []
    for obj in objects.values():
        if obj.tag == 'GXDLMSProfileGeneric':
            validate_profile(obj)
            rows = len(obj.find('Buffer'))
            count = obj.find('EntriesInUse')
            if count is not None:
                count.text = str(rows)
            profiles.append({'logical_name': obj.findtext('LN'), 'rows': rows, 'columns': len(obj.find('CaptureObjects'))})
    if model(root) != original_model:
        raise ValueError('Object model changed')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    ET.indent(tree, space='  ')
    tree.write(output_path, encoding='utf-8', xml_declaration=True)
    report = {'base': paths[0].name, 'meter_type': selected_category[0], 'category': selected_category[1],
              'sources': [{'name': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths],
              'output': output_path.name, 'output_sha256': hashlib.sha256(output_path.read_bytes()).hexdigest(),
              'model_unchanged': model(ET.parse(output_path).getroot()) == original_model,
              'objects': len(objects), 'imported_profiles': replacements, 'profiles': profiles,
              'explicitly_replaced_profiles': sorted(replaced),
              'push_setups': [o.findtext('LN') for o in objects.values() if o.tag == 'GXDLMSPushSetup'],
              'timestamp_policy': 'Source timestamps retained; simulator runtime supplies current clock and shifts profile recency.'}
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--donor', action='append', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--replace-profile', action='append', default=[], help='Explicitly replace one existing buffer after model compatibility checks')
    args = parser.parse_args()
    result = compose(args.base, args.donor, args.output, args.report, args.replace_profile)
    print(json.dumps({k: result[k] for k in ('output', 'objects', 'model_unchanged', 'imported_profiles')}))
