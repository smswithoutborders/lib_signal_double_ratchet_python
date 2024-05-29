"""
SMSWithoutBorders' cryptographic library implements Signal's Double Ratchet 
algorithm and other essential cryptographic functions utilized throughout 
SMSWithoutBorders projects.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    readme = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [req.strip() for req in fh.readlines()]

with open("VERSION", "r", encoding="utf-8") as f:
    version = f.read().strip()

setup(
    name="smswithoutborders_libsig",
    version=version,
    description="SMSWithoutBorders' cryptographic library implements Signal's "
    "Double Ratchet algorithm and other essential cryptographic functions "
    "used throughout SMSWithoutBorders projects.",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/smswithoutborders/lib_signal_double_ratchet_python",
    author="Afkanerd",
    author_email="developers@smswithoutborders.com",
    license="GPLv3",
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3 :: Only",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
)
