try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote


from flask import jsonify

__author__ = "michowdh@cisco.com"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__version__ = "0.2"
__status__ = "alpha"


class DbException(Exception):
    status_code = 400

    def __init__(self, e, status=None, payload=None):
        Exception.__init__(self)
        self.message = e.args[0]
        if status is not None:
            self.status = status
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv




