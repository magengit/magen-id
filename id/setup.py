from setuptools import setup
import sys
import os
import pip

with open(os.path.join(os.path.dirname(__file__), '__init__.py')) as version_file:
    exec(version_file.read())

if sys.version_info < (3, 5, 2):
    sys.exit("Sorry, you need Python 3.5.2+")

pip_version = int(pip.__version__.replace(".", ""))
if pip_version < 901:
        sys.exit("Sorry, you need pip 9.0.1+")

setup(
    name='magen_id_service',
    version=__version__,
    packages={"id",
        "id.id_service", 
        "id.id_service.magenid",
        "id.id_service.magenid.idsapp",
        "id.id_service.magenid.idsapp.idsserver",
        "id.id_service.magenid.idsapp.idsserver.lib",
        "id.id_service.magenid.idsapp.idsserver.lib.db",
        "id.id_service.magenid.idsapp.idsserver.lib.db.models",
        "id.id_service.magenid.idsapp.idsserver.lib.bll",
        "id.id_service.magenid.idsapp.idsserver.lib.oidc",
        "id.id_service.magenid.idsapp.idsserver.rest",
        "id.id_service.magenid.idsapp.idsserver.utils",
        "id.id_service.magenid.idsapp.idsserver.views",
        "id.id_service.magenid.idsapp.idsserver.views.oauth",
        "id.id_service.magenid.idsapp.templates" },

    install_requires=[
        'aniso8601>=1.2.1',
        'consulate>=0.6.0',
        'coverage>=4.4.1',
        'ipython>=6.1.0',
        'flake8>=3.3.0',
        'flask-ldap3-login>=0.9.12',
        'flask-restful>=0.3.6',
        'Flask>=0.12.2',
        'Flask-Cors>=3.0.3',
        'Flask-Login>=0.2.11',
        'mongoengine>=0.13.0',
        'freezegun>=0.3.9',
        'passlib>=1.7.1',
        'PyJWT>=1.5.2',
        'pycrypto>=2.6.1',
        'pymongo>=3.4.0',
        'pytest>=3.1.3',
        'requests>=2.13.0',
        'responses>=0.5.1',
        'Sphinx>=1.6.3',
        'wheel>=0.30.0a0',
        'mock>=2.0',
        'magen_logger==1.0a1',
        'magen_utils==1.0a1',
        # 'magen_test_utils==1.0a1',
        'magen_mongo>=1.1a',
        'magen_datastore>=1.0a',
        'magen_rest_service==1.0a1',
        'magen_statistics_service==1.0a1'
    ],

    scripts=[
        'id_service/id_server.py',
        'id_scripts/id_server_wrapper.sh'],
    include_package_data=True,
    package_dir={'': '..'},
    package_data={
        '': ['*.txt', '*.rst', '*.html']
    },
    test_suite='tests',
    url='',
    license='Proprietary License',
    author='Mizanul Chowdhury',
    author_email='michowdh@cisco.com',
    description='Magen ID Service Package',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 2 - Pre-Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Education',
        'Intended Audience :: Financial and Insurance Industry',
        'Intended Audience :: Healthcare Industry',
        'Intended Audience :: Legal Industry',
        'Topic :: Security',

        # Pick your license as you wish (should match "license" above)
        'License :: Other/Proprietary License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.5',
    ],
)
