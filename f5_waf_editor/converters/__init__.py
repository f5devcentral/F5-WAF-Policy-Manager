"""
BIG-IP WAF Policy Converter package.
Supports converting legacy BIG-IP ASM / Advanced WAF exported policies (JSON format) to F5 WAF for NGINX JSON declarative policies.
"""

from .bigip_converter import (
    BigIpPolicyConverter,
    convert_bigip_policy,
    convert_bigip_policy_json,
    convert_bigip_policy_xml,
)

__all__ = [
    "BigIpPolicyConverter",
    "convert_bigip_policy",
    "convert_bigip_policy_json",
    "convert_bigip_policy_xml",
]
