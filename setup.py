import setuptools

setuptools.setup(
    name='saltpack',
    version='0.0.1',
    license='MIT',
    py_modules=['saltpack'],
    # package_data={'saltpack': 'unicode'},
    entry_points={
        'console_scripts': [
            'saltpack=saltpack.main:main',
        ]
    },
)
