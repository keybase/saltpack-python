import setuptools

setuptools.setup(
    name='saltpack',
    version='0.0.1',
    license='MIT',
    packages=['saltpack'],
    package_data={'saltpack': ['unicode/*']},
    install_requires=['docopt', 'libnacl', 'u-msgpack-python'],
    entry_points={
        'console_scripts': [
            'saltpack=saltpack.main:main',
        ]
    },
)
