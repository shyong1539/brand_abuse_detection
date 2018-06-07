
# -*- coding: utf-8 -*-
import codecs
import os
import re
import whois
import dnstwist
import string
import json
from email import parser, message_from_string
from dns import resolver


class BrandAbuseDetection:

    def __init__(self, texts):
        self.cwd = os.getcwd()
        self.headers = message_from_string(texts)
        self.target_brands = self.twisty_domain()
        self.phish_words = self.phishy_words()

    # Parse email address
    def parse_email(self, from_header):
        from_header = from_header.decode('utf-8')
        match = re.findall(r'[\w\.-]+@[\w\.-]+', from_header, re.UNICODE)
        return match

    # Determine if a host domain is good
    def is_domain_legit(self, domain):
        good_domain = False
        while domain.find('.') > 0:
            try:
                answers = resolver.query(domain, rdtype="SOA")
                for rdata in answers:
                    # print (rdata)
                    good_domain = True
                break
            except:
                domain = domain[domain.find('.') + 1:]
        return good_domain

    # Determine if a domain is spoofed
    def is_domain_spoofed(self, target):
        domain_spoofed = False
        cwd = self.cwd + '/data/'
        for brand in self.target_brands:
            lines = []
            with codecs.open(cwd + brand + '.fuzz', 'r', encoding='utf-8') as rf:
                for line in rf:
                    lines.append(line.strip())
            domain = lines[0]
            # print 'is_domain_spoofed ' + domain
            if target in lines[1:]:
                domain_spoofed = True
                break
        return domain_spoofed, domain

    # Parse email headers from texts provided
    def parse_email_header(self, texts):
        # print 'Texts = {}'.format(texts)
        headers = parser.Parser().parsestr(texts, headersonly=True)
        for header in headers.keys():
            print '{0} is {1}'.format(header, headers[header])
        # print 'Headers Subject = {}'.format(headers['Subject'])
        return headers

    # Brand name permutation using brand_abuse_detection
    def twisty_domain(self):
        target_brands = []
        # print (os.getcwd())
        with open(self.cwd + "/data/brands.txt") as fh:
            for line in fh:
                name = line.strip().translate(None, string.whitespace)
                name_fuzz = self.cwd + "/data/" + name + ".fuzz"
                target_brands.append(name)
                if not os.path.isfile(name_fuzz):
                    fuzz = dnstwist.DomainFuzz(name + ".com")
                    fuzz.generate()
                    with open(name_fuzz, 'w') as wf:
                        for domain in fuzz.domains:
                            wf.write(domain['domain-name'].encode('utf-8') + '\n')
        return target_brands

    # Obtain a list of frequently used keyword in phishing attacks
    def phishy_words(self):
        phish_words = []
        with open(self.cwd + "/data/phish_words.txt") as fh:
            for line in fh:
                phish_words.append(line.strip().encode('utf-8'))
        return phish_words

    # Detect suspicious subject line
    def is_subject_suspicious(self, subject_line=None):

        if subject_line is None:
            subject_line = self.headers['Subject']
        ss = subject_line.split()
        hints = []
        for s in ss:
            s = s.lower()
            if s in self.target_brands:
                hints.append(s)
            else:
                for w in self.phish_words:
                    if w in s:
                        hints.append(w)
        if len(hints) > 0:
            words = ', '.join(w for w in hints)
            reason = 'Subject line contains ' + words
            return [{'header': 'Subject', 'text': subject_line, 'reason': reason, 'category': 'Suspicious subject'}]
        else:
            return None

    # Detect suspicious sender
    def is_sender_suspicious(self, from_email=None):

        if from_email is None:
            from_email = self.headers['From'] + ' ' + self.headers['Return-Path']
        email_parsed = self.parse_email(from_email)

        email_parsed = set(email_parsed)
        if len(email_parsed) > 1:
            suspicious_sender = True
            emails = ' '.join(e for e in email_parsed)
            reason = 'Sender has multiple email identities ' + emails
            return [{'header': 'From & Return-Path', 'text': from_email, 'reason': reason, 'category': 'Suspicious Sender'}]
        else:
            return None

    # Detect suspicious email domain
    def is_email_suspicious(self, from_email=None):
        if from_email is None:
            from_email = self.headers['From']
        delchars = ''.join(c for c in map(chr, range(256)) if not c.isalnum())
        # python 3
        # scrunched = from_email.translate({ord(c):'' for c in delchars})
        # python 2
        scrunched = from_email.translate(None, delchars)
        scrunched = scrunched.lower()
        hints = []
        for b in self.target_brands:
            if b in scrunched:
                hints.append(b)
                break
        for w in self.phish_words:
            if w in scrunched:
                hints.append(w)
                break
        if len(hints) == 2:
            reason = 'Sender email has a combination of {0} and {1}'.format(hints[0], hints[1])
            return [{'header': 'From', 'text': from_email, 'category': 'Suspicious Email', 'reason': reason}]
        else:
            return None

    # detect spoofed sender
    def is_domain_compromised(self, from_email=None):
        if from_email is None:
            from_email = self.headers['From']
        email_parsed = self.parse_email(from_email)
        myregex = r'(?:[(\w+)](?:[(\w+)\-]{,61}[(\w+)])?\.)+[a-zA-Z]{2,6}'
        hints = []
        for email in email_parsed:
            domains = re.findall(myregex, email, re.UNICODE)
            for domain in domains:
                flag, target = self.is_domain_spoofed(domain)
                if flag:
                    reason = domain + ' is a spoof of ' + target.strip()
                    hints.append({'header': 'From', 'text': from_email, 'category': 'Spoofed Domain', 'reason': reason})
                flag = self.is_domain_legit(domain)
                if not flag:
                    reason = domain + ' is not a legitimate Top Level Domain'
                    hints.append({'header': 'From', 'text': from_email, 'category': 'Illicit Domain', 'reason': reason})

        if len(hints) > 0:
            return hints
        else:
            return None

    # Given email headers in text, this API will categorize this email as trusted, suspicious or malicious
    # based on the following indicators:
    #
    # 1. suspicious_subject - where the subject line contains phishy key words
    # 2. suspicious_sender  - who has two different email addresses in the 'From'
    # 3. suspicious_brand   - where a brand name that was the most frequently phished was in the 'From'
    # 4. illicit_domain     - whose domain failed 'WHOIS' check
    # 5. spoofed_domain     - whose domain matched by brand_abuse_detection domain permutation
    #
    # To determine whether an email is trusted, suspicious or malicious, we may
    #
    # 1. An equal weight is given to all suspicious key indicators, a threshold is set on the count of
    #    suspicious indicators may determine the email suspicious categories.
    # 2. An uneven weight system assign different weights to the suspicious key indicators and a normalized
    #    score may be calculated based the weighted suspicious indicator.  Then email suspicious category can
    #    be mapped to a range of scores.
    def categorize_email(self, json_out=False):

        suspicious_matrix = {'Title': 'Suspicious Matrix'}

        factors = []

        suspicious_subject = self.is_subject_suspicious()
        if suspicious_subject is not None:
            for s in suspicious_subject:
                factors.append(s)

        suspicious_sender = self.is_sender_suspicious()
        if suspicious_sender is not None:
            for s in suspicious_sender:
                factors.append(s)

        suspicious_brand = self.is_email_suspicious()
        if suspicious_brand is not None:
            for s in suspicious_brand:
                factors.append(s)

        compromised_domain = self.is_domain_compromised()
        if compromised_domain is not None:
            for s in compromised_domain:
                factors.append(s)

        suspicious_matrix['factors'] = factors

        if json_out:
            return json.dumps(suspicious_matrix, encoding='utf-8')
        else:
            return suspicious_matrix


def main():

    texts = ''

    with open(os.getcwd() + '/data/email_headers.txt', 'r') as rf:
        for line in rf:
            texts += line

    bad = BrandAbuseDetection(texts)

    suspicious_matrix = bad.categorize_email()
    json_object = json.dumps(suspicious_matrix, indent=4, sort_keys=True)
    json_object_loaded = json.loads(json_object)
    print json_object


if __name__ == '__main__':
    main()
