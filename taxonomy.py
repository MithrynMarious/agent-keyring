"""Key taxonomy CLI — agent archetypes, key shapes, and service mapping.

EPIC-KEYRING-220 S-12/S-13. Maps the keyring's secrets to archetypes,
surfaces gaps, suggests routing for new services, and browses
the ecosystem-wide service catalog.

Usage:
  python taxonomy.py profile          # show current keyring mapped to archetypes
  python taxonomy.py gaps             # show missing services per archetype
  python taxonomy.py suggest <svc>    # suggest archetype + key shape for a service
  python taxonomy.py shapes           # list key shapes with descriptions
  python taxonomy.py archetypes       # list agent archetypes
  python taxonomy.py ecosystem [cat]  # browse ecosystem registry (optional category filter)
  python taxonomy.py lookup <svc>     # look up any service across taxonomy + ecosystem
"""

import argparse
import json
import os
import sys

_DIR = os.path.dirname(os.path.abspath(__file__))
TAXONOMY_PATH = os.path.join(_DIR, "taxonomy.json")
MANIFEST_PATH = os.path.join(_DIR, "secret_manifest.json")
PERMISSIONS_PATH = os.path.join(_DIR, "permissions.json")
ECOSYSTEM_PATH = os.path.join(_DIR, "ecosystem_registry.json")


def _load(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _taxonomy():
    return _load(TAXONOMY_PATH)


def _manifest():
    return _load(MANIFEST_PATH)


def _permissions():
    return _load(PERMISSIONS_PATH)


def _ecosystem():
    return _load(ECOSYSTEM_PATH)


def cmd_profile(args):
    """Show current keyring mapped to archetypes."""
    tax = _taxonomy()
    manifest = _manifest()
    perms = _permissions()
    secrets = manifest.get("secrets", {})
    services = tax.get("services", {})
    archetypes = tax.get("archetypes", {})

    svc_to_secrets = {}
    for svc_name, svc_info in services.items():
        matched = [s for s in svc_info.get("keyring_secrets", []) if s in secrets]
        if matched:
            svc_to_secrets[svc_name] = matched

    arch_coverage = {}
    for arch_name, arch_info in archetypes.items():
        covered = []
        missing = []
        for svc in arch_info.get("typical_services", []):
            if svc in svc_to_secrets:
                covered.append(svc)
            else:
                missing.append(svc)
        extra = [
            svc for svc, info in services.items()
            if arch_name in info.get("archetypes", []) and svc in svc_to_secrets and svc not in covered
        ]
        covered.extend(extra)
        arch_coverage[arch_name] = {
            "covered": covered,
            "missing": missing,
            "agents": arch_info.get("city_agents", []),
            "description": arch_info.get("description", ""),
        }

    print("KEYRING PROFILE")
    print("=" * 60)
    print(f"Secrets: {len(secrets)} registered")
    print(f"Services: {len(svc_to_secrets)} with keys / {len(services)} in taxonomy")
    print()

    for arch_name, info in arch_coverage.items():
        covered_count = len(info["covered"])
        total = covered_count + len(info["missing"])
        pct = (covered_count / total * 100) if total else 0
        bar = _bar(pct)

        agents_str = ", ".join(info["agents"]) if info["agents"] else "none assigned"
        print(f"  {arch_name.upper():14s} {bar} {pct:3.0f}%  ({agents_str})")
        print(f"  {' ':14s} {info['description']}")

        if info["covered"]:
            print(f"  {' ':14s} have: {', '.join(info['covered'])}")
        if info["missing"]:
            print(f"  {' ':14s} gap:  {', '.join(info['missing'])}")
        print()

    unmapped = [
        name for name in secrets
        if not any(name in info.get("keyring_secrets", []) for info in services.values())
    ]
    if unmapped:
        print(f"  UNMAPPED SECRETS: {', '.join(unmapped)}")
        print(f"  (not linked to any service in taxonomy.json)")
        print()

    agent_profiles = {}
    for agent_id, allowed in perms.items():
        if agent_id.startswith("_"):
            continue
        agent_name = agent_id.split("@")[0] if "@" in agent_id else agent_id
        agent_archs = set()
        for svc_name, svc_info in services.items():
            svc_secrets = svc_info.get("keyring_secrets", [])
            if any(s in allowed for s in svc_secrets):
                for arch in svc_info.get("archetypes", []):
                    agent_archs.add(arch)
        agent_profiles[agent_name] = sorted(agent_archs)

    if agent_profiles:
        print("AGENT ARCHETYPE PROFILES (from permissions)")
        print("-" * 60)
        for agent, archs in sorted(agent_profiles.items()):
            print(f"  {agent:20s} {', '.join(archs) if archs else 'no archetype coverage'}")
        print()


def cmd_gaps(args):
    """Show missing services per archetype."""
    tax = _taxonomy()
    manifest = _manifest()
    secrets = manifest.get("secrets", {})
    services = tax.get("services", {})
    archetypes = tax.get("archetypes", {})
    shapes = tax.get("key_shapes", {})

    svc_with_keys = {
        svc_name for svc_name, svc_info in services.items()
        if any(s in secrets for s in svc_info.get("keyring_secrets", []))
    }

    print("GAP ANALYSIS")
    print("=" * 60)
    total_gaps = 0

    for arch_name, arch_info in archetypes.items():
        gaps = []
        for svc in arch_info.get("typical_services", []):
            if svc not in svc_with_keys:
                svc_info = services.get(svc, {})
                shape = svc_info.get("key_shape", "unknown")
                shape_desc = shapes.get(shape, {}).get("description", "")
                gaps.append((svc, shape, shape_desc))

        additional = [
            (svc, info.get("key_shape", "unknown"))
            for svc, info in services.items()
            if arch_name in info.get("archetypes", []) and svc not in svc_with_keys
            and svc not in arch_info.get("typical_services", [])
        ]

        if not gaps and not additional:
            continue

        total_gaps += len(gaps) + len(additional)
        print(f"\n  {arch_name.upper()} ({arch_info.get('description', '')})")
        print(f"  {'-' * 50}")

        for svc, shape, _ in gaps:
            env_vars = services.get(svc, {}).get("env_var_names", [])
            env_str = f"  env: {', '.join(env_vars)}" if env_vars else ""
            print(f"    [{shape:15s}] {svc}{env_str}")

        for svc, shape in additional:
            print(f"    [{shape:15s}] {svc} (related)")

    if total_gaps == 0:
        print("  No gaps found. All typical services have keys.")
    else:
        print(f"\n  Total gaps: {total_gaps}")
    print()


def cmd_suggest(args):
    """Suggest archetype + key shape for a new service."""
    service_name = args.service.lower().strip()
    tax = _taxonomy()
    services = tax.get("services", {})
    archetypes = tax.get("archetypes", {})
    shapes = tax.get("key_shapes", {})

    if service_name in services:
        svc = services[service_name]
        shape = svc.get("key_shape", "unknown")
        archs = svc.get("archetypes", [])
        env_vars = svc.get("env_var_names", [])
        keyring_secrets = svc.get("keyring_secrets", [])
        notes = svc.get("notes", "")

        print(f"SERVICE: {service_name}")
        print(f"  Key shape:   {shape} — {shapes.get(shape, {}).get('description', '')}")
        print(f"  Archetypes:  {', '.join(archs)}")
        print(f"  Env vars:    {', '.join(env_vars)}")
        print(f"  Keyring:     {', '.join(keyring_secrets)}")
        if notes:
            print(f"  Notes:       {notes}")

        print(f"\n  Suggested agents:")
        for arch in archs:
            agents = archetypes.get(arch, {}).get("city_agents", [])
            print(f"    {arch}: {', '.join(agents) if agents else 'none assigned'}")
        return

    matches = _fuzzy_match(service_name, services, archetypes)
    if matches:
        print(f"SERVICE: {service_name} (not in registry)")
        print(f"\n  Similar services in registry:")
        for name, score in matches[:5]:
            svc = services[name]
            print(f"    {name} ({svc.get('key_shape', '?')}) — {', '.join(svc.get('archetypes', []))}")

        best = services[matches[0][0]]
        print(f"\n  Best guess based on '{matches[0][0]}':")
        print(f"    Key shape:  {best.get('key_shape', 'bearer')} (most common for similar services)")
        print(f"    Archetypes: {', '.join(best.get('archetypes', []))}")
    else:
        print(f"SERVICE: {service_name} (unknown)")
        print(f"  No similar services found. Default suggestion:")
        print(f"    Key shape:  bearer (most common)")
        print(f"    Archetype:  builder (default for unknown services)")
        print(f"    Env var:    {service_name.upper().replace('-', '_')}_API_KEY")


def cmd_shapes(args):
    """List key shapes."""
    tax = _taxonomy()
    shapes = tax.get("key_shapes", {})
    services = tax.get("services", {})

    print("KEY SHAPES")
    print("=" * 60)
    for name, info in shapes.items():
        svc_count = sum(1 for s in services.values() if s.get("key_shape") == name)
        print(f"\n  {name.upper()} ({svc_count} services)")
        print(f"  {info.get('description', '')}")
        print(f"  Rotation: {info.get('rotation', 'N/A')}")
        print(f"  Risk:     {info.get('risk', 'N/A')}")
        examples = info.get("examples", [])
        if examples:
            print(f"  Examples: {', '.join(examples[:3])}")


def cmd_archetypes(args):
    """List agent archetypes."""
    tax = _taxonomy()
    archetypes = tax.get("archetypes", {})
    services = tax.get("services", {})

    print("AGENT ARCHETYPES")
    print("=" * 60)
    for name, info in archetypes.items():
        svc_list = [
            svc for svc, svc_info in services.items()
            if name in svc_info.get("archetypes", [])
        ]
        print(f"\n  {name.upper()}")
        print(f"  {info.get('description', '')}")
        print(f"  Key shapes: {', '.join(info.get('typical_key_shapes', []))}")
        print(f"  Agents:     {', '.join(info.get('city_agents', []))}")
        print(f"  Services:   {', '.join(svc_list)}")


def cmd_ecosystem(args):
    """Browse the ecosystem service registry by category."""
    eco = _ecosystem()
    categories = eco.get("categories", {})
    tax = _taxonomy()
    manifest = _manifest()
    secrets = manifest.get("secrets", {})
    tax_services = tax.get("services", {})

    tax_svc_names = set()
    for svc_name, svc_info in tax_services.items():
        if any(s in secrets for s in svc_info.get("keyring_secrets", [])):
            tax_svc_names.add(svc_name)

    if args.category:
        cat_key = args.category.lower().replace(" ", "_").replace("-", "_")
        matches = [
            (k, v) for k, v in categories.items()
            if cat_key in k or cat_key in v.get("description", "").lower()
        ]
        if not matches:
            print(f"No category matching '{args.category}'. Available:")
            for k, v in sorted(categories.items()):
                print(f"  {k:22s} {v.get('description', '')}")
            return
        for cat_name, cat in matches:
            _print_category(cat_name, cat, tax_svc_names)
    else:
        print("ECOSYSTEM SERVICE REGISTRY")
        print("=" * 70)
        total_services = sum(len(c.get("services", {})) for c in categories.values())
        have_count = 0
        for cat in categories.values():
            for svc_name in cat.get("services", {}):
                if svc_name in tax_svc_names:
                    have_count += 1
        print(f"  {len(categories)} categories, {total_services} services "
              f"({have_count} in City keyring)")
        print()
        for cat_name, cat in sorted(categories.items()):
            svcs = cat.get("services", {})
            have = sum(1 for s in svcs if s in tax_svc_names)
            print(f"  {cat_name:22s} {len(svcs):2d} services  "
                  f"({have} active)  {cat.get('description', '')}")
        print(f"\n  Use: python taxonomy.py ecosystem <category> for details")


def _print_category(cat_name, cat, active_names):
    """Print detailed view of one ecosystem category."""
    print(f"\n{'=' * 70}")
    print(f"  {cat_name.upper().replace('_', ' ')}")
    print(f"  {cat.get('description', '')}")
    print(f"  Default archetype: {cat.get('archetype', 'N/A')}")
    print(f"{'=' * 70}")

    services = cat.get("services", {})
    for svc_name, svc in sorted(services.items()):
        active = svc_name in active_names
        marker = "[*]" if active else "[ ]"
        mcp = " (MCP)" if svc.get("has_mcp") else ""
        print(f"\n  {marker} {svc_name}{mcp}")
        print(f"      Shape:   {svc.get('key_shape', '?')}")
        print(f"      Pattern: {svc.get('key_pattern', '?')}")
        print(f"      Env:     {', '.join(svc.get('env_vars', []))}")
        print(f"      Auth:    {svc.get('auth_header', '?')}")
        if svc.get("notes"):
            print(f"      Notes:   {svc['notes']}")

    mcp_services = [s for s, info in services.items() if info.get("has_mcp")]
    if mcp_services:
        print(f"\n  MCP servers available: {', '.join(mcp_services)}")
    print()


def cmd_lookup(args):
    """Look up a service across both taxonomy and ecosystem registry."""
    query = args.service.lower().strip()
    tax = _taxonomy()
    eco = _ecosystem()
    manifest = _manifest()
    secrets = manifest.get("secrets", {})
    tax_services = tax.get("services", {})
    shapes = tax.get("key_shapes", {})

    if query in tax_services:
        svc = tax_services[query]
        has_keys = any(s in secrets for s in svc.get("keyring_secrets", []))
        print(f"SERVICE: {query} {'[ACTIVE]' if has_keys else '[not configured]'}")
        print(f"  Source:      City taxonomy (taxonomy.json)")
        print(f"  Key shape:   {svc.get('key_shape', '?')} — "
              f"{shapes.get(svc.get('key_shape', ''), {}).get('description', '')}")
        print(f"  Archetypes:  {', '.join(svc.get('archetypes', []))}")
        print(f"  Env vars:    {', '.join(svc.get('env_var_names', []))}")
        print(f"  Keyring:     {', '.join(svc.get('keyring_secrets', []))}")
        if svc.get("notes"):
            print(f"  Notes:       {svc['notes']}")

    eco_hit = None
    eco_cat = None
    for cat_name, cat in eco.get("categories", {}).items():
        if query in cat.get("services", {}):
            eco_hit = cat["services"][query]
            eco_cat = cat_name
            break

    if eco_hit:
        if query in tax_services:
            print(f"\n  --- Also in ecosystem registry ({eco_cat}) ---")
        else:
            print(f"SERVICE: {query}")
            print(f"  Source:      Ecosystem registry ({eco_cat})")
        print(f"  Key shape:   {eco_hit.get('key_shape', '?')}")
        print(f"  Pattern:     {eco_hit.get('key_pattern', '?')}")
        print(f"  Env vars:    {', '.join(eco_hit.get('env_vars', []))}")
        print(f"  Auth:        {eco_hit.get('auth_header', '?')}")
        mcp = "yes" if eco_hit.get("has_mcp") else "no"
        print(f"  MCP server:  {mcp}")
        if eco_hit.get("notes"):
            print(f"  Notes:       {eco_hit['notes']}")
    elif query not in tax_services:
        all_eco = {}
        for cat_name, cat in eco.get("categories", {}).items():
            for svc_name in cat.get("services", {}):
                all_eco[svc_name] = cat_name

        combined = dict.fromkeys(list(tax_services.keys()) + list(all_eco.keys()))
        matches = _fuzzy_match(query, combined, {})
        if matches:
            print(f"SERVICE: {query} (not found)")
            print(f"\n  Similar services:")
            for name, score in matches[:5]:
                source = "taxonomy" if name in tax_services else f"ecosystem/{all_eco.get(name, '?')}"
                print(f"    {name} ({source})")
        else:
            print(f"SERVICE: {query} (unknown)")
            print(f"  Not found in taxonomy or ecosystem registry.")
            print(f"  Default suggestion: bearer key, builder archetype")
            print(f"  Env var: {query.upper().replace('-', '_')}_API_KEY")


def _bar(pct, width=20):
    filled = int(pct / 100 * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"


def _fuzzy_match(query, services, archetypes):
    scores = []
    for name in services:
        score = 0
        if query in name:
            score += 3
        if name in query:
            score += 2
        common = set(query) & set(name)
        score += len(common) / max(len(query), len(name))
        if score > 0.5:
            scores.append((name, score))
    return sorted(scores, key=lambda x: -x[1])


def main():
    parser = argparse.ArgumentParser(
        description="Key taxonomy — agent archetypes, key shapes, and service mapping"
    )
    subs = parser.add_subparsers(dest="command")

    subs.add_parser("profile", help="Show current keyring mapped to archetypes")
    subs.add_parser("gaps", help="Show missing services per archetype")

    suggest_p = subs.add_parser("suggest", help="Suggest archetype for a service")
    suggest_p.add_argument("service", help="Service name to look up")

    subs.add_parser("shapes", help="List key shapes")
    subs.add_parser("archetypes", help="List agent archetypes")

    eco_p = subs.add_parser("ecosystem", help="Browse ecosystem service registry")
    eco_p.add_argument("category", nargs="?", default=None,
                       help="Category to show (payments, ai_ml, monitoring, etc.)")

    lookup_p = subs.add_parser("lookup", help="Look up a service across all registries")
    lookup_p.add_argument("service", help="Service name to look up")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    handlers = {
        "profile": cmd_profile,
        "gaps": cmd_gaps,
        "suggest": cmd_suggest,
        "shapes": cmd_shapes,
        "archetypes": cmd_archetypes,
        "ecosystem": cmd_ecosystem,
        "lookup": cmd_lookup,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
