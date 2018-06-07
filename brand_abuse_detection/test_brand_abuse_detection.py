# -*- coding: utf-8 -*-

import unittest

from brand_abuse_detection import *


class TestBrandAbuseDetection(unittest.TestCase):

    texts = ''

    with open(os.getcwd() + '/data/email_headers.txt', 'r') as rf:
        for line in rf:
            texts += line

    bad = BrandAbuseDetection(texts)

    def test_is_subject_suspicious(self):
        print 'test_is_subject_suspicious ...'
        self.assertTrue(self.bad.is_subject_suspicious() is not None)

    def test_is_sender_suspicious(self):
        print 'test_is_sender_suspicious'
        self.assertTrue(self.bad.is_sender_suspicious() is not None)

    def test_is_email_suspicious(self):
        print 'test_is_domain_suspicious'
        self.assertTrue(self.bad.is_email_suspicious() is not None)

    def test_is_domain_compromised(self):
        print 'test_is_domain_compromised'
        self.assertTrue(self.bad.is_domain_compromised() is not None)

    def test_categorize_email_dict(self):
        print 'test_categorize_email with output in dictionary'
        self.assertTrue(self.bad.categorize_email() is not None)

    def test_categorize_email_json(self):
        print 'test_categorize_email with output in json'
        self.assertTrue(self.bad.categorize_email(json_out=True) is not None)
