import os, json, time, pytest
from unittest.mock import patch
from moto import mock_aws
import boto3

from integrations.aws.aws_inventory import enrich_kms_with_tags, enrich_acm_with_tags, DEFAULT_CONTEXT

@mock_aws
def test_kms_enrich_defaults_and_tags():
    kms = boto3.client('kms', region_name='us-east-1')
    # create key without tags
    key_meta = kms.create_key(Description='test key')
    key_id = key_meta['KeyMetadata']['KeyId']
    arn = key_meta['KeyMetadata']['Arn']
    ctx = enrich_kms_with_tags(kms, arn)
    # Should have defaults because no tags
    for k,v in DEFAULT_CONTEXT.items():
        assert ctx.get(k) == v
    # Now add tags including owner
    kms.tag_resource(KeyId=key_id, Tags=[{'TagKey':'Owner','TagValue':'TeamA'},{'TagKey':'DataClass','TagValue':'restricted'},{'TagKey':'SecrecyYears','TagValue':'5'}])
    ctx2 = enrich_kms_with_tags(kms, arn)
    assert ctx2['owner'] == 'TeamA'
    assert ctx2['data_class'] == 'restricted'
    assert ctx2['secrecy_lifetime_years'] == 5.0

@mock_aws
def test_acm_enrich_pagination_and_defaults():
    acm = boto3.client('acm', region_name='us-east-1')
    # create certificates (moto limited simulation) - we'll just test tag listing logic fallback
    arn_list = []
    for i in range(3):
        cert = acm.import_certificate(Certificate=b"---CERT---", PrivateKey=b"---KEY---")
        arn_list.append(cert['CertificateArn'])
    # tag only first cert
    acm.add_tags_to_certificate(CertificateArn=arn_list[0], Tags=[{'Key':'Owner','Value':'TeamB'}])
    c0 = enrich_acm_with_tags(acm, arn_list[0])
    c1 = enrich_acm_with_tags(acm, arn_list[1])
    assert c0['owner'] == 'TeamB'
    assert c1['owner'] == DEFAULT_CONTEXT['owner']

@mock_aws
def test_throttling_retry_monkeypatch():
    kms = boto3.client('kms', region_name='us-east-1')
    key_meta = kms.create_key(Description='retry key')
    arn = key_meta['KeyMetadata']['Arn']
    calls = {'n':0}
    real = kms.list_resource_tags
    def flaky(**kwargs):
        calls['n'] += 1
        if calls['n'] < 3:
            raise Exception('Throttling: Rate exceeded')
        return real(**kwargs)
    with patch.object(kms, 'list_resource_tags', side_effect=flaky):
        ctx = enrich_kms_with_tags(kms, arn)
    assert calls['n'] == 3
    assert ctx['owner'] == DEFAULT_CONTEXT['owner']
