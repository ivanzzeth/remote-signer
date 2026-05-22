#!/usr/bin/env python3
"""
Batch-replace hardcoded addresses in template test_cases with ${variable} references.

For each template file in rules/templates/:
1. Reads test_variables to build address→variable mappings
2. Replaces exact address matches in test_cases sections with ${var}
3. Replaces padded-hex addresses in calldata with ${paddedhex:var}
4. For known repeating test signer addresses not in test_variables, auto-adds them
"""

import os
import re
import sys
import json

TEMPLATES_DIR = "rules/templates/evm"

# Common test signer addresses used across many templates
# These will be auto-added as variables if missing
COMMON_SIGNERS = {
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266": "signer_address_for_testing",
    "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4": "recipient_address_for_testing",
    "0x88eD75e9eCE373997221E3c0229e74007C1AD718": "signer_address_for_testing",  # polymarket real signer
    "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837": "allowed_safe_address_for_testing",
}

# Addresses that are OK to keep as-is (sentinel / test-only values)
SENTINEL_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002",
    "0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD",
    "0xdEAD000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dEaD",
    "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
    "0x000000000000000000000000000000000000dead",
    "0x1111111111111111111111111111111111111111",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
}


def extract_section(content, section_name):
    """Extract a named top-level YAML section. Returns (start_line, end_line, text) or None."""
    lines = content.split('\n')
    in_section = False
    section_lines = []
    start = None
    indent = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not in_section and re.match(r'^' + re.escape(section_name) + r'\s*:', stripped):
            in_section = True
            start = i
            indent = len(line) - len(line.lstrip())
            section_lines.append(line)
            continue
        if in_section:
            if stripped == '' or stripped.startswith('#'):
                section_lines.append(line)
                continue
            current_indent = len(line) - len(line.lstrip())
            # Check if this is a new top-level key (less or equal indent than the section header)
            if current_indent <= indent and not stripped.startswith('-') and ':' in stripped:
                break
            section_lines.append(line)

    if start is not None:
        return (start, start + len(section_lines), '\n'.join(section_lines))
    return None


def parse_kv_pairs(text):
    """Parse simple key: value pairs from YAML text."""
    pairs = {}
    for line in text.split('\n'):
        m = re.match(r'^(\s+)(\w+):\s*(.+)$', line)
        if m:
            key = m.group(2)
            val = m.group(3).strip().strip('"').strip("'")
            pairs[key] = val
    return pairs


def parse_yaml_value(raw):
    """Parse a YAML value, handling quotes."""
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    return raw


def find_test_variables(content):
    """Find test_variables section and return dict."""
    section = extract_section(content, 'test_variables')
    if not section:
        return {}
    return parse_kv_pairs(section[2])


def find_variables_defs(content):
    """Find variables definitions and return list of {name, type, required, default}."""
    section = extract_section(content, 'variables')
    if not section:
        return []

    text = section[2]
    vars_list = []
    # Parse list items under variables:
    current = {}
    for line in text.split('\n'):
        stripped = line.strip()
        # New list item
        if stripped.startswith('- name:'):
            if current:
                vars_list.append(current)
            current = {'name': stripped.split(':', 1)[1].strip().strip('"').strip("'")}
        elif current:
            m = re.match(r'^(\s+)-\s+(\w+):\s*(.+)$', line)
            if m:
                current[m.group(2)] = parse_yaml_value(m.group(3))
            elif re.match(r'^\s+(\w+):\s*(.+)$', line):
                m2 = re.match(r'^\s+(\w+):\s*(.+)$', line)
                if m2 and m2.group(1) != 'name':
                    current[m2.group(1)] = parse_yaml_value(m2.group(2))

    if current:
        vars_list.append(current)
    return vars_list


def find_hardcoded_addresses(text, exclude_set=None):
    """Find all hardcoded 0x-prefixed addresses in text."""
    if exclude_set is None:
        exclude_set = SENTINEL_ADDRESSES

    # Match 0x followed by exactly 40 hex chars (standard Ethereum address)
    pattern = r'0x[a-fA-F0-9]{40}'
    matches = set(re.findall(pattern, text))

    # Filter out sentinel addresses
    result = set()
    for addr in matches:
        if addr.lower() not in {a.lower() for a in exclude_set}:
            result.add(addr)

    return result


def build_address_var_map(test_vars, var_defs):
    """Build mappings from address value → variable name."""
    # Direct: "0xABCD" → ${var}
    direct_map = {}
    # Padded hex in calldata: "0000...00ABCD" → ${paddedhex:var}
    padded_map = {}

    for var_def in var_defs:
        name = var_def['name']
        vtype = var_def.get('type', '')
        if vtype in ('address', 'string') and name in test_vars:
            val = test_vars[name]
            if val.startswith('0x') and len(val) == 42:
                # Direct replacement
                direct_map[val.lower()] = ('${' + name + '}', name)
                # Padded hex (lowercase, no 0x prefix, left-padded to 64)
                hex_val = val[2:].lower()
                padded = '0' * (64 - len(hex_val)) + hex_val
                padded_map[padded] = ('${paddedhex:' + name + '}', name)
                # Also with 0x
                padded_map['0x' + padded] = ('${paddedhex:' + name + '}', name)

    return direct_map, padded_map


def is_within_test_cases(text, pos):
    """Check if position is inside a test_cases section."""
    before = text[:pos]
    # Count test_cases: occurrences before this position
    # If the last occurrence is after the last top-level key, we're in test_cases
    # Simple heuristic: find last "test_cases:" and check we haven't hit another top-level key since

    # Find all test_cases markers
    tc_pos = before.rfind('test_cases:')
    if tc_pos == -1:
        return False

    # Check if there's a top-level key (^word:) after the last test_cases:
    after_tc = before[tc_pos:]
    # If we see something like "^rules:" or another top-level key, we've left test_cases
    for m in re.finditer(r'^(\w+):', after_tc, re.MULTILINE):
        if m.group(1) != 'test_cases':
            # This is after test_cases and is a top-level key
            remaining = text[tc_pos:]
            # Find this key in remaining
            key_pos = remaining.find(m.group(0))
            if key_pos > 0:  # Not the test_cases: itself
                return False

    return True


def replace_in_test_cases(content, direct_map, padded_map, filepath):
    """Replace addresses in test_cases sections only."""
    result = content

    # Split into before_test_cases, test_cases, and after
    tc_section = extract_section(result, 'test_cases')
    if not tc_section:
        return result, []

    tc_start, tc_end, tc_text = tc_section
    lines = result.split('\n')
    tc_lines = lines[tc_start:tc_end]
    tc_content = '\n'.join(tc_lines)

    changes = []

    # Process padded hex replacements first (longer strings, more specific)
    # Sort by length descending to avoid partial matches
    sorted_padded = sorted(padded_map.items(), key=lambda x: -len(x[0]))

    for old_padded, (new_val, varname) in sorted_padded:
        # Search in tc_content
        idx = 0
        while True:
            pos = tc_content.find(old_padded, idx)
            if pos == -1:
                break

            # Check context: the padded address should be inside calldata hex
            # (inside a string that starts with 0x and contains many hex chars)
            # Simple check: it's inside a longer hex string
            start = max(0, pos - 10)
            context_before = tc_content[start:pos]

            # Make sure we're in a hex data context (not in a variable definition)
            tc_content = tc_content[:pos] + new_val + tc_content[pos + len(old_padded):]
            changes.append(f"  paddedhex {varname}: {old_padded[:16]}... → {new_val}")
            idx = pos + len(new_val)

    # Process direct address replacements
    sorted_direct = sorted(direct_map.items(), key=lambda x: -len(x[0]))

    for addr_lower, (new_val, varname) in sorted_direct:
        # Match the address in various contexts:
        # 1. As a quoted value: "0xABCD"
        # 2. As an unquoted value: 0xABCD
        # But NOT inside a longer hex string (that's padded replacement territory)
        # We match the exact address (case-insensitive for the address part)
        idx = 0
        while True:
            # Find the address (any case)
            pattern = re.compile(re.escape(addr_lower), re.IGNORECASE)
            m = pattern.search(tc_content, idx)
            if not m:
                break

            match_start = m.start()
            match_end = m.end()

            # Verify we're NOT inside a longer hex string
            # Check the character before: if it's a hex digit, we're inside a longer string
            before_char = tc_content[match_start - 1] if match_start > 0 else ''
            after_char = tc_content[match_end] if match_end < len(tc_content) else ''

            if before_char in '0123456789abcdefABCDEF' or after_char in '0123456789abcdefABCDEF':
                idx = match_end
                continue

            # Also check: this should be in test_cases context
            matched_addr = tc_content[match_start:match_end]
            tc_content = tc_content[:match_start] + new_val + tc_content[match_end:]
            changes.append(f"  direct {varname}: {matched_addr[:20]}... → {new_val}")
            idx = match_start + len(new_val)

    # Reconstruct
    new_lines = tc_content.split('\n')
    lines[tc_start:tc_end] = new_lines
    result = '\n'.join(lines)

    return result, changes


def add_test_variable(content, varname, value):
    """Add a key: value to test_variables section."""
    section = extract_section(content, 'test_variables')
    if section:
        start, end, text = section
        lines = content.split('\n')
        # Find the last line in test_variables that has content (not blank, not comment)
        last_content = end
        for i in range(end - 1, start - 1, -1):
            stripped = lines[i].strip()
            if stripped and not stripped.startswith('#'):
                last_content = i + 1
                break

        # Find the indent level from existing entries
        indent = "  "
        for i in range(start, end):
            if re.match(r'^\s+\w+:', lines[i]):
                indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
                break

        new_line = f"{indent}{varname}: \"{value}\""
        lines.insert(last_content, new_line)
        return '\n'.join(lines)
    else:
        # No test_variables section, add one after variables (or at top level)
        var_section = extract_section(content, 'variables')
        if var_section:
            insert_at = var_section[1]
        else:
            insert_at = 0

        lines = content.split('\n')
        lines.insert(insert_at, 'test_variables:')
        lines.insert(insert_at + 1, f'  {varname}: "{value}"')
        lines.insert(insert_at + 2, '')
        return '\n'.join(lines)


def add_variable_def(content, name, vtype='address', required=False, description='', default_val=''):
    """Add a variable definition to the variables list."""
    var_section = extract_section(content, 'variables')
    if var_section:
        start, end, text = var_section
        lines = content.split('\n')
        # Find indent from existing entries
        indent = "  "
        for i in range(start, end):
            stripped = lines[i].strip()
            if stripped.startswith('- name:'):
                indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
                break

        # Find last variable to insert after
        last_var_line = end - 1
        for i in range(end - 1, start - 1, -1):
            stripped = lines[i].strip()
            if stripped and not stripped.startswith('#'):
                last_var_line = i + 1
                break

        new_lines = [
            f"{indent}- name: {name}",
            f"{indent}  type: {vtype}",
            f"{indent}  description: \"{description}\"",
            f"{indent}  required: false",
        ]
        if default_val:
            new_lines.append(f"{indent}  default: \"{default_val}\"")

        for i, nl in enumerate(new_lines):
            lines.insert(last_var_line + i, nl)

        return '\n'.join(lines)
    return content


def process_file(filepath, dry_run=True):
    """Process a single template file."""
    with open(filepath, 'r') as f:
        original = f.read()

    content = original
    filename = os.path.basename(filepath)
    all_changes = []
    vars_added = []

    # Get existing data
    test_vars = find_test_variables(content)
    var_defs = find_variables_defs(content)
    existing_var_names = {v['name'] for v in var_defs}

    # Find hardcoded addresses in test_cases only
    tc_section = extract_section(content, 'test_cases')
    if not tc_section:
        return None  # No test_cases

    tc_text = tc_section[2]
    hardcoded_addrs = find_hardcoded_addresses(tc_text)
    if not hardcoded_addrs:
        return None  # No hardcoded addresses to fix

    # Check which addresses match test_variables
    direct_map, padded_map = build_address_var_map(test_vars, var_defs)

    # For addresses not in test_vars, try COMMON_SIGNERS
    additions_needed = {}
    for addr in hardcoded_addrs:
        addr_lower = addr.lower()
        # Check if already mappable
        if addr_lower in direct_map:
            continue
        # Check if it's a known common signer
        if addr in COMMON_SIGNERS:
            varname = COMMON_SIGNERS[addr]
            additions_needed[addr] = varname

    if additions_needed:
        for addr, varname in additions_needed.items():
            if varname in test_vars:
                # Already in test_vars (different value?), update direct_map
                pass
            else:
                # Add test_variable
                description = f"Test {varname.replace('_for_testing', '').replace('_', ' ')} address"
                if varname not in existing_var_names:
                    if not dry_run:
                        content = add_variable_def(content, varname, default_val=addr,
                                                    description=description)
                    vars_added.append(f"  + variable: {varname} = {addr}")
                if not dry_run:
                    content = add_test_variable(content, varname, addr)
                vars_added.append(f"  + test_variable: {varname} = {addr}")

        # Rebuild maps after adding
        test_vars = find_test_variables(content)
        var_defs = find_variables_defs(content)
        direct_map, padded_map = build_address_var_map(test_vars, var_defs)

    # Now do the replacement
    result, changes = replace_in_test_cases(content, direct_map, padded_map, filepath)

    if changes or vars_added:
        return {
            'file': filename,
            'changes': changes,
            'vars_added': vars_added,
            'new_content': result if not dry_run else None,
            'unmapped': hardcoded_addrs - {a.lower() for a in direct_map.keys()} if False else set(),
        }

    return None


def main():
    dry_run = '--apply' not in sys.argv
    if dry_run:
        print("=== DRY RUN MODE === (pass --apply to write changes)\n")
    else:
        print("=== APPLY MODE ===\n")

    all_results = []
    for fname in sorted(os.listdir(TEMPLATES_DIR)):
        if not fname.endswith(('.yaml', '.yml')):
            continue
        fpath = os.path.join(TEMPLATES_DIR, fname)
        result = process_file(fpath, dry_run=dry_run)
        if result:
            all_results.append(result)
            print(f"\n{'='*60}")
            print(f"FILE: {result['file']}")
            print(f"{'='*60}")
            for v in result.get('vars_added', []):
                print(v)
            for c in result['changes']:
                print(c)

    unmapped_all = set()
    for r in all_results:
        unmapped_all.update(r.get('unmapped', set()))

    print(f"\n\n{'='*60}")
    print(f"SUMMARY: {len(all_results)} files with changes")
    print(f"{'='*60}")

    if unmapped_all:
        print(f"\n⚠ UNMAPPED ADDRESSES (need manual review):")
        for a in sorted(unmapped_all):
            print(f"  {a}")
    else:
        print(f"\n✓ All addresses mapped")

    if dry_run and all_results:
        print(f"\nRun with --apply to write changes")

    if not dry_run:
        print(f"\n✓ Changes applied to {len(all_results)} files")


if __name__ == '__main__':
    main()
