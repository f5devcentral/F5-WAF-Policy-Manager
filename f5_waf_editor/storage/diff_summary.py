"""
Diff and Change Summary Generator for GitOps Commit Messages.

Generates concise, human-readable, multi-line commit descriptions
highlighting changes between clean upstream baselines and local drafts
for F5 WAF for NGINX policies, logging profiles, and custom signatures.
"""

import json
from typing import Any, Dict, List, Optional, Set, Union


def _parse_dict(val: Any) -> Optional[Dict[str, Any]]:
    if isinstance(val, dict):
        return val
    if isinstance(val, str) and val.strip():
        try:
            parsed = json.loads(val)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return None
    return None


def summarize_policy_changes(
    old_data: Optional[Union[dict, str]],
    new_data: Optional[Union[dict, str]],
    policy_name: str,
) -> str:
    """
    Generate a concise, multi-line commit description highlighting
    the specific changes made to a WAF policy.
    """
    old_dict = _parse_dict(old_data)
    new_dict = _parse_dict(new_data) or {}

    old_p = old_dict.get("policy", old_dict) if old_dict else {}
    new_p = new_dict.get("policy", new_dict) if new_dict else {}

    # Case 1: Initial creation (did not exist previously on GitHub)
    if not old_p:
        subject = f"feat(waf): create policy '{policy_name}'"
        bullets = []
        tmpl = new_p.get("template", {}).get("name") if isinstance(new_p.get("template"), dict) else None
        if tmpl:
            bullets.append(f"Template: {tmpl}")
        enf = new_p.get("enforcementMode")
        if enf:
            bullets.append(f"Enforcement mode: {enf}")
        techs = [
            t.get("serverTechnologyName")
            for t in new_p.get("server-technologies", [])
            if isinstance(t, dict) and t.get("serverTechnologyName")
        ]
        if techs:
            bullets.append(f"Server technologies: {', '.join(techs[:5])}{' (+' + str(len(techs)-5) + ' more)' if len(techs) > 5 else ''}")
        sig_sets = new_p.get("signature-sets", [])
        if sig_sets:
            bullets.append(f"Signature sets: {len(sig_sets)} configured")
        urls = new_p.get("urls", [])
        if urls:
            bullets.append(f"Allowed URLs: {len(urls)} configured")
        params = new_p.get("parameters", [])
        if params:
            bullets.append(f"Parameters: {len(params)} configured")

        if not bullets:
            bullets.append("Initial baseline policy configuration")

        return f"{subject}\n\nInitial policy configuration:\n" + "\n".join(f"- {b}" for b in bullets)

    # Case 2: Policy Update
    subject = f"feat(waf): update policy '{policy_name}'"
    changes: List[str] = []

    # 1. Enforcement mode
    old_enf = old_p.get("enforcementMode")
    new_enf = new_p.get("enforcementMode")
    if old_enf != new_enf and (old_enf or new_enf):
        changes.append(f"Enforcement mode: changed from '{old_enf}' to '{new_enf}'")

    # 2. Template
    old_tmpl = old_p.get("template", {}).get("name") if isinstance(old_p.get("template"), dict) else None
    new_tmpl = new_p.get("template", {}).get("name") if isinstance(new_p.get("template"), dict) else None
    if old_tmpl != new_tmpl and (old_tmpl or new_tmpl):
        changes.append(f"Base template: changed from '{old_tmpl}' to '{new_tmpl}'")

    # 3. Description
    old_desc = (old_p.get("description") or "").strip()
    new_desc = (new_p.get("description") or "").strip()
    if old_desc != new_desc and (old_desc or new_desc):
        changes.append("Updated policy description")

    # 4. Server Technologies
    old_techs = {
        t.get("serverTechnologyName")
        for t in old_p.get("server-technologies", [])
        if isinstance(t, dict) and t.get("serverTechnologyName")
    }
    new_techs = {
        t.get("serverTechnologyName")
        for t in new_p.get("server-technologies", [])
        if isinstance(t, dict) and t.get("serverTechnologyName")
    }
    added_techs = sorted(list(new_techs - old_techs))
    removed_techs = sorted(list(old_techs - new_techs))
    if added_techs and removed_techs:
        changes.append(f"Server technologies: added {', '.join(added_techs)}; removed {', '.join(removed_techs)}")
    elif added_techs:
        changes.append(f"Server technologies: added {', '.join(added_techs)}")
    elif removed_techs:
        changes.append(f"Server technologies: removed {', '.join(removed_techs)}")

    # 5. Signature Sets
    old_ss = {s.get("name"): s for s in old_p.get("signature-sets", []) if isinstance(s, dict) and s.get("name")}
    new_ss = {s.get("name"): s for s in new_p.get("signature-sets", []) if isinstance(s, dict) and s.get("name")}
    added_ss = sorted(list(set(new_ss.keys()) - set(old_ss.keys())))
    removed_ss = sorted(list(set(old_ss.keys()) - set(new_ss.keys())))
    modified_ss = []
    for ss_name in set(old_ss.keys()) & set(new_ss.keys()):
        s_old, s_new = old_ss[ss_name], new_ss[ss_name]
        flag_diffs = []
        if s_old.get("alarm") != s_new.get("alarm"):
            flag_diffs.append(f"alarm={'on' if s_new.get('alarm') else 'off'}")
        if s_old.get("block") != s_new.get("block"):
            flag_diffs.append(f"block={'on' if s_new.get('block') else 'off'}")
        if flag_diffs:
            modified_ss.append(f"{ss_name} ({', '.join(flag_diffs)})")

    if added_ss:
        changes.append(f"Signature sets added: {', '.join(added_ss)}")
    if removed_ss:
        changes.append(f"Signature sets removed: {', '.join(removed_ss)}")
    if modified_ss:
        changes.append(f"Signature sets updated: {', '.join(modified_ss)}")

    # 6. Signatures (Individual Overrides)
    old_sigs = {s.get("signatureId") or s.get("name"): s for s in old_p.get("signatures", []) if isinstance(s, dict)}
    new_sigs = {s.get("signatureId") or s.get("name"): s for s in new_p.get("signatures", []) if isinstance(s, dict)}
    added_sigs = len(set(new_sigs.keys()) - set(old_sigs.keys()))
    removed_sigs = len(set(old_sigs.keys()) - set(new_sigs.keys()))
    if added_sigs and removed_sigs:
        changes.append(f"Signatures: added {added_sigs} override(s), removed {removed_sigs} override(s)")
    elif added_sigs:
        changes.append(f"Signatures: added {added_sigs} override(s)")
    elif removed_sigs:
        changes.append(f"Signatures: removed {removed_sigs} override(s)")

    # 7. URLs
    old_urls = {u.get("name"): u for u in old_p.get("urls", []) if isinstance(u, dict) and u.get("name")}
    new_urls = {u.get("name"): u for u in new_p.get("urls", []) if isinstance(u, dict) and u.get("name")}
    added_urls = sorted([str(u) for u in (set(new_urls.keys()) - set(old_urls.keys()))])
    removed_urls = sorted([str(u) for u in (set(old_urls.keys()) - set(new_urls.keys()))])
    if added_urls and removed_urls:
        changes.append(f"URLs: added {', '.join(added_urls[:3])}{' (+' + str(len(added_urls)-3) + ' more)' if len(added_urls) > 3 else ''}; removed {', '.join(removed_urls[:3])}")
    elif added_urls:
        changes.append(f"URLs: added {', '.join(added_urls[:4])}{' (+' + str(len(added_urls)-4) + ' more)' if len(added_urls) > 4 else ''}")
    elif removed_urls:
        changes.append(f"URLs: removed {', '.join(removed_urls[:4])}{' (+' + str(len(removed_urls)-4) + ' more)' if len(removed_urls) > 4 else ''}")

    # 8. Parameters
    old_params = {p.get("name"): p for p in old_p.get("parameters", []) if isinstance(p, dict) and p.get("name")}
    new_params = {p.get("name"): p for p in new_p.get("parameters", []) if isinstance(p, dict) and p.get("name")}
    added_params = sorted([str(p) for p in (set(new_params.keys()) - set(old_params.keys()))])
    removed_params = sorted([str(p) for p in (set(old_params.keys()) - set(new_params.keys()))])
    if added_params and removed_params:
        changes.append(f"Parameters: added {', '.join(added_params[:3])}; removed {', '.join(removed_params[:3])}")
    elif added_params:
        changes.append(f"Parameters: added {', '.join(added_params[:4])}{' (+' + str(len(added_params)-4) + ' more)' if len(added_params) > 4 else ''}")
    elif removed_params:
        changes.append(f"Parameters: removed {', '.join(removed_params[:4])}")

    # 9. Cookies
    old_cookies = {c.get("name"): c for c in old_p.get("cookies", []) if isinstance(c, dict) and c.get("name")}
    new_cookies = {c.get("name"): c for c in new_p.get("cookies", []) if isinstance(c, dict) and c.get("name")}
    added_cookies = sorted([str(c) for c in (set(new_cookies.keys()) - set(old_cookies.keys()))])
    removed_cookies = sorted([str(c) for c in (set(old_cookies.keys()) - set(new_cookies.keys()))])
    if added_cookies or removed_cookies:
        c_parts = []
        if added_cookies:
            c_parts.append(f"added {', '.join(added_cookies[:3])}")
        if removed_cookies:
            c_parts.append(f"removed {', '.join(removed_cookies[:3])}")
        changes.append(f"Cookies: {'; '.join(c_parts)}")

    # 10. Blocking Settings & Violations
    old_bs = old_p.get("blocking-settings", {}) if isinstance(old_p.get("blocking-settings"), dict) else {}
    new_bs = new_p.get("blocking-settings", {}) if isinstance(new_p.get("blocking-settings"), dict) else {}
    old_viols = {v.get("name"): v for v in old_bs.get("violations", []) if isinstance(v, dict) and v.get("name")}
    new_viols = {v.get("name"): v for v in new_bs.get("violations", []) if isinstance(v, dict) and v.get("name")}
    viol_diffs = []
    for vname in sorted(list(set(old_viols.keys()) | set(new_viols.keys()))):
        ov, nv = old_viols.get(vname, {}), new_viols.get(vname, {})
        if ov.get("block") != nv.get("block") or ov.get("alarm") != nv.get("alarm"):
            action = "blocked" if nv.get("block") else ("alarmed" if nv.get("alarm") else "disabled")
            viol_diffs.append(f"{vname} ({action})")
    if viol_diffs:
        changes.append(f"Violations updated: {', '.join(viol_diffs[:3])}{' (+' + str(len(viol_diffs)-3) + ' more)' if len(viol_diffs) > 3 else ''}")

    # 11. Data Guard
    old_dg = old_p.get("data-guard", {}) if isinstance(old_p.get("data-guard"), dict) else {}
    new_dg = new_p.get("data-guard", {}) if isinstance(new_p.get("data-guard"), dict) else {}
    if old_dg.get("enabled") != new_dg.get("enabled"):
        status = "enabled" if new_dg.get("enabled") else "disabled"
        changes.append(f"Data Guard: {status}")
    elif old_dg != new_dg and new_dg:
        changes.append("Data Guard: updated data masking/credit card rules")

    # 12. Bot Defense
    old_bot = old_p.get("bot-defense", {}) if isinstance(old_p.get("bot-defense"), dict) else {}
    new_bot = new_p.get("bot-defense", {}) if isinstance(new_p.get("bot-defense"), dict) else {}
    if old_bot != new_bot and (old_bot or new_bot):
        changes.append("Bot Defense: updated mitigation settings")

    # 13. Other Sections
    checked_sections = {
        "enforcementMode", "template", "description", "server-technologies",
        "signature-sets", "signatures", "urls", "parameters", "cookies",
        "blocking-settings", "data-guard", "bot-defense", "name",
    }
    other_sections = []
    for k in set(old_p.keys()) | set(new_p.keys()):
        if k not in checked_sections and old_p.get(k) != new_p.get(k):
            other_sections.append(k)
    if other_sections:
        changes.append(f"Updated configuration sections: {', '.join(sorted(other_sections)[:4])}")

    if not changes:
        changes.append("Minor configuration and parameter adjustments")

    return f"{subject}\n\nChanges:\n" + "\n".join(f"- {c}" for c in changes)


def summarize_log_profile_changes(
    old_data: Optional[Union[dict, str]],
    new_data: Optional[Union[dict, str]],
    profile_name: str,
) -> str:
    """
    Generate a concise, multi-line commit description highlighting
    the specific changes made to a logging profile.
    """
    old_dict = _parse_dict(old_data)
    new_dict = _parse_dict(new_data) or {}

    old_f = old_dict.get("filter", {}) if old_dict and isinstance(old_dict.get("filter"), dict) else {}
    new_f = new_dict.get("filter", {}) if isinstance(new_dict.get("filter"), dict) else {}
    old_c = old_dict.get("content", {}) if old_dict and isinstance(old_dict.get("content"), dict) else {}
    new_c = new_dict.get("content", {}) if isinstance(new_dict.get("content"), dict) else {}

    # Case 1: Initial creation
    if not old_dict:
        subject = f"feat(logging): create logging profile '{profile_name}'"
        bullets = []
        if new_f.get("request_type"):
            bullets.append(f"Request type: {new_f.get('request_type')}")
        if new_c.get("format"):
            bullets.append(f"Storage format: {new_c.get('format')}")
        if new_c.get("max_message_size"):
            bullets.append(f"Max message size: {new_c.get('max_message_size')}")
        if not bullets:
            bullets.append("Initial baseline logging profile configuration")
        return f"{subject}\n\nInitial logging profile configuration:\n" + "\n".join(f"- {b}" for b in bullets)

    # Case 2: Update
    subject = f"feat(logging): update logging profile '{profile_name}'"
    changes: List[str] = []

    # 1. Request type
    old_rt = old_f.get("request_type")
    new_rt = new_f.get("request_type")
    if old_rt != new_rt and (old_rt or new_rt):
        changes.append(f"Request type: changed from '{old_rt}' to '{new_rt}'")

    # 2. Format
    old_fmt = old_c.get("format")
    new_fmt = new_c.get("format")
    if old_fmt != new_fmt and (old_fmt or new_fmt):
        changes.append(f"Storage format: changed from '{old_fmt}' to '{new_fmt}'")

    # 3. Format string
    if old_c.get("format_string") != new_c.get("format_string") and (old_c.get("format_string") or new_c.get("format_string")):
        changes.append("Updated log format template string")

    # 4. Message & Request size
    if old_c.get("max_message_size") != new_c.get("max_message_size") and (old_c.get("max_message_size") or new_c.get("max_message_size")):
        changes.append(f"Max message size: changed from '{old_c.get('max_message_size')}' to '{new_c.get('max_message_size')}'")
    if old_c.get("max_request_size") != new_c.get("max_request_size") and (old_c.get("max_request_size") or new_c.get("max_request_size")):
        changes.append(f"Max request size: changed from '{old_c.get('max_request_size')}' to '{new_c.get('max_request_size')}'")

    # 5. Escaping
    if old_c.get("escaping") != new_c.get("escaping") and (old_c.get("escaping") or new_c.get("escaping")):
        changes.append(f"Escaping: changed to '{new_c.get('escaping')}'")

    # 6. Description
    if old_f.get("description") != new_f.get("description") and (old_f.get("description") or new_f.get("description")):
        changes.append("Updated profile description")

    if not changes:
        changes.append("Updated logging profile configuration and filter attributes")

    return f"{subject}\n\nChanges:\n" + "\n".join(f"- {c}" for c in changes)


def summarize_custom_signatures_changes(
    old_data: Optional[Union[dict, str]],
    new_data: Optional[Union[dict, str]],
    tag: str,
) -> str:
    """
    Generate a concise commit description for custom signature files.
    """
    old_dict = _parse_dict(old_data)
    new_dict = _parse_dict(new_data) or {}

    old_sigs = old_dict.get("signatures", []) if old_dict and isinstance(old_dict.get("signatures"), list) else []
    new_sigs = new_dict.get("signatures", []) if isinstance(new_dict.get("signatures"), list) else []

    if not old_sigs and not old_dict:
        return f"feat(signatures): create custom signature set '{tag}'\n\nInitial configuration:\n- Configured {len(new_sigs)} custom signature(s)"

    count_diff = len(new_sigs) - len(old_sigs)
    changes = []
    if count_diff > 0:
        changes.append(f"Added {count_diff} new custom signature(s) (total: {len(new_sigs)})")
    elif count_diff < 0:
        changes.append(f"Removed {abs(count_diff)} custom signature(s) (total: {len(new_sigs)})")
    else:
        changes.append(f"Updated custom signature definitions and patterns (total: {len(new_sigs)})")

    return f"feat(signatures): update custom signatures '{tag}'\n\nChanges:\n" + "\n".join(f"- {c}" for c in changes)
