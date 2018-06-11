import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="brand_abuse_detection",
    version="0.1.1",
    author="emoryshyong",
    author_email ="emory@clearedin.com",
    description = "Brand Abuse Detectione",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/shyong1539/brand_abuse_detection",
    packages = setuptools.find_packages(),
    install_requires=[
        'GeoIP',
        'dnspython',
        'requests',
        'requests',
        'whois'
    ],
    classifiers = (
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
