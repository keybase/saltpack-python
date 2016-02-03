import setuptools

import saltpack

setuptools.setup(
    name='saltpack',
    version=saltpack.__version__,
    license='MIT',
    author="Jack O'Connor",
    author_email="oconnor663+pypi@gmail.com",
    url="https://github.com/keybase/saltpack-python",
    packages=['saltpack'],
    package_data={'saltpack': ['unicode/*']},
    install_requires=['docopt', 'libnacl', 'u-msgpack-python'],
    entry_points={
        'console_scripts': [
            'saltpack=saltpack.main:main',
        ]
    },
)
