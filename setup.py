# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
import os, sys
# from Gallimaufry.Version import version
here = os.path.abspath(os.path.dirname(__file__))

long_description = "See website for more info."

version = '0.0.1'

setup(
    name='binPwn',
    version=version,
    description='Tool to simplify common binary exploitation and fuzzing tasks.',
    long_description=long_description,
    url='https://github.com/bannsec/autoPwn',
    author='Michael Bann',
    author_email='self@bannsecurity.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console'
    ],
    extras_require={
        'dev': ['six','ipython','twine','pytest','python-coveralls','coverage','pytest-cov','pytest-xdist','sphinxcontrib-napoleon', 'sphinx_rtd_theme','sphinx-autodoc-typehints'],
    },
    install_requires=["prettytable","termcolor"],
    keywords='pwn exploitation',
    packages=find_packages(exclude=['contrib', 'docs', 'tests','lib','examples']),
    entry_points={
        'console_scripts': [
            'autoPwn = autoPwn.autoPwn:main',
        ],
    },
)


