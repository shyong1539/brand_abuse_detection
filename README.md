Brand Abuse Detection

Given email haders, we attempt to extract email addresses, domain names and
subject line to check the valiidity domain name and email address and phish
related functional words existing in the headers

The output by the API (categorize_email) is a dictionary or an optional json
object.  There are five suspicious factors:

1. Suspicious Subject
2. Suspicious Email
3. Suspicious Sender
4. Illicit Domain
5. Spoofed Domain

The output in json looks like the following:

{
    "Title": "Suspicious Matrix",
    "factors": [
        {
            "category": "Suspicious subject",
            "header": "Subject",
            "reason": "Subject line contains citi, fund",
            "text": "Citi Warrants on $25 Million Funding"
        },
        {
            "category": "Suspicious Sender",
            "header": "From & Return-Path",
            "reason": "Sender has multiple email identities Microsoft_Support@ib\u043c.com Good_Guy@tech.com ceo_yahoo@yahoo.com.jp",
            "text": "\"Microsoft_Support@ib\u043c.com\" <ceo_yahoo@yahoo.com.jp > CEO Good_Guy@tech.com"
        },
        {
            "category": "Suspicious Email",
            "header": "From",
            "reason": "Sender email has a combination of microsoft and support",
            "text": "\"Microsoft_Support@ib\u043c.com\" <ceo_yahoo@yahoo.com.jp >"
        },
        {
            "category": "Spoofed Domain",
            "header": "From",
            "reason": "ib\u043c.com is a spoof of ibm.com",
            "text": "\"Microsoft_Support@ib\u043c.com\" <ceo_yahoo@yahoo.com.jp >"
        },
        {
            "category": "Illicit Domain",
            "header": "From",
            "reason": "ib\u043c.com is not a legitimate Top Level Domain",
            "text": "\"Microsoft_Support@ib\u043c.com\" <ceo_yahoo@yahoo.com.jp >"
        },
        {
            "category": "Illicit Domain",
            "header": "From",
            "reason": "yahoo.com.jp is not a legitimate Top Level Domain",
            "text": "\"Microsoft_Support@ib\u043c.com\" <ceo_yahoo@yahoo.com.jp >"
        }
    ]
}


There is a main() in brand_abuse_detection.py that emulates the API (categorize_email).

For example:

def main():

    texts = ''

    with open(os.getcwd() + '/data/email_headers.txt', 'r') as rf:
        for line in rf:
            texts += line

    bad = BrandAbuseDetection(texts)

    suspicious_matrix = bad.categorize_email()


JSON object can be return if

    json_object = bad.categorize_email(json_out=True)


dnstwist Requirements
---------------------

DNSTWIST library is required.  Please follow the instruction below to install
dnstwist.

**Linux**

Ubuntu Linux is the primary development platform. If running Ubuntu 15.04 or
newer, you can install dependencies like this:

```
$ sudo apt-get install python-dnspython python-geoip python-whois \
python-requests python-ssdeep python-cffi
```

Alternately, you can use Python tooling. This can be done within a virtual
environment to avoid conflicts with other installations. However, you will
still need a couple of libraries installed at the system level.

```
$ sudo apt-get install libgeoip-dev libffi-dev
$ BUILD_LIB=1 pip install -r requirements.txt
```

**OSX**

If you're on a Mac, you can install dnstwist via
[Homebrew](https://github.com/Homebrew/homebrew) like so:

```
$ brew install dnstwist
```

This is going to install `dnstwist.py` as `dnstwist` only, along with all
requirements mentioned above. The usage is the same, you can just omit the
file extension, and the binary will be added to `PATH`.

**Docker**

If you use Docker, you can pull official image from Docker Hub and run it:

```
$ docker pull elceef/dnstwist
$ docker run elceef/dnstwist example.com
```
