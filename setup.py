import setuptools

with open("saltpack/VERSION") as f:
    version = f.read().strip()

setuptools.setup(
    name='saltpack',
    version=version,
    license='MIT',
    author="Jack O'Connor",
    author_email="oconnor663+pypi@gmail.com",
    url="https://github.com/keybase/saltpack-python",
    packages=['saltpack'],
    package_data={'saltpack': ['VERSION', 'unicode/*']},
    install_requires=['docopt', 'libnacl', 'u-msgpack-python'],
    entry_points={
        'console_scripts': [
            'saltpack=saltpack.main:main',
        ]
    },
)
