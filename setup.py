from distutils.core import setup
import sys
import io

NAME = 'ipinformation'
VERSION = '1.0.21'
AUTHOR = 'neu5ron'
AUTHOR_EMAIL = 'therealneu5ron AT gmail DOT com'
DESCRIPTION = "Combine information about an ip address in JSON format"
URL = "https://github.com/neu5ron/ipinformation"
DOWNLOAD_URL = "https://github.com/neu5ron/ipinformation/tarball/master"

LONG_DESCRIPTION = '\n\n'.join([io.open('README.md', 'r',
                                        encoding='utf-8').read(),
                                io.open('CHANGES.md', 'r',
                                        encoding='utf-8').read()])


PACKAGES = ['ipinformation']


INSTALL_REQUIRES = []


if sys.version_info >= (3,):
    print 'Requires python 2.7.'
    sys.exit(1)
else:
    INSTALL_REQUIRES.append("requests[security]")
    INSTALL_REQUIRES.append("pygeoip")
    INSTALL_REQUIRES.append("netaddr")
    INSTALL_REQUIRES.append("ipwhois")
    INSTALL_REQUIRES.append("dateutils")
    INSTALL_REQUIRES.append("dnspython")

setup(
    name=NAME,
    version=VERSION,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    url=URL,
    download_url=DOWNLOAD_URL,
    packages=PACKAGES,
    install_requires=INSTALL_REQUIRES
)