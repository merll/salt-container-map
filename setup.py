# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

from saltcontainermap import __version__


setup(
    name='salt-container-map',
    version=__version__,
    packages=find_packages(),
    install_requires=['salt', 'docker-map>=0.4.0'],
    url='',
    license='MIT',
    author='Matthias Erll',
    author_email='matthias@erll.de',
    description='Configuration management and implicit dependency setup for Docker containers in SaltStack.',
    platforms=['OS Independent'],
    keywords=['docker', 'deployment', 'salt'],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Build Tools',
        'Topic :: System :: Software Distribution',
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
    ],
    entry_points={
        'console_scripts': [
            'install_container_map = saltcontainermap.modinstall:install_modules',
            'uninstall_container_map = saltcontainermap.modinstall:remove_modules',
        ],
    },
    include_package_data=True,
)
