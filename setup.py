import os.path
from setuptools import setup
from teleparser import VERSION


# The directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))

# The text of the README file
with open(os.path.join(HERE, "README.md")) as fid:
    README = fid.read()

setup(
    name="teleparser",
    version=VERSION,
    long_description_content_type="text/markdown",
    long_description=README,
    install_requires=["construct==2.10.68"],
    packages=["teleparser"],
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "teleparser = teleparser.run:main",
        ]
    },
)
