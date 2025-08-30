


import time
from typing import Callable, Any, Dict, List

TAG_OWNER_KEYS = ["Owner","owner","OWNER","AppOwner","ApplicationOwner"]
TAG_DATA_CLASS_KEYS = ["DataClass","DataClassification","Classification"]
TAG_SECRECY_KEYS = ["SecrecyYears","Secrecy_Lifetime_Years","SecrecyLifetime"]

DEFAULT_CONTEXT = {
    "owner": "unknown",
    "data_class": "unclassified",
    "secrecy_lifetime_years": 10,
    "exposure": "internal",
}

def _with_throttle_retry(fn: Callable[[], Any], retries: int = 3, base_delay: float = 0.2):
    for attempt in range(retries):
        try:
            return fn()
        except Exception as e:  # in practice catch botocore throttling errors
            msg = str(e)
            if "Throttl" in msg or "Rate exceeded" in msg:
                if attempt == retries - 1:
                    raise
                time.sleep(base_delay * (2 ** attempt))
                continue
            raise
    return None

def _infer_context_from_tags(tags: dict) -> dict:
    owner = None
    data_class = None
    secrecy = None
    for k in TAG_OWNER_KEYS:
        if k in tags: owner = tags[k]; break
    for k in TAG_DATA_CLASS_KEYS:
        if k in tags: data_class = tags[k]; break
    for k in TAG_SECRECY_KEYS:
        if k in tags:
            try:
                secrecy = float(tags[k])
            except Exception:
                secrecy = None
            break
    ctx = {"owner": owner, "data_class": data_class, "secrecy_lifetime_years": secrecy}
    # apply defaults where missing
    for dk, dv in DEFAULT_CONTEXT.items():
        if ctx.get(dk) in (None, ""):
            ctx[dk] = dv
    return ctx

def _tags_to_dict(tag_list):
    out = {}
    for t in tag_list or []:
        k = t.get("TagKey") or t.get("Key")
        v = t.get("TagValue") or t.get("Value")
        if k: out[k] = v
    return out


def enrich_kms_with_tags(kms_client, key_arn: str) -> dict:
    try:
        resp = _with_throttle_retry(lambda: kms_client.list_resource_tags(KeyId=key_arn))
        tags = _tags_to_dict(resp.get("Tags", [])) if resp else {}
        return _infer_context_from_tags(tags)
    except Exception:
        return DEFAULT_CONTEXT.copy()

def enrich_acm_with_tags(acm_client, cert_arn: str) -> dict:
    try:
        resp = _with_throttle_retry(lambda: acm_client.list_tags_for_certificate(CertificateArn=cert_arn))
        tags = _tags_to_dict(resp.get("Tags", [])) if resp else {}
        return _infer_context_from_tags(tags)
    except Exception:
        return DEFAULT_CONTEXT.copy()
