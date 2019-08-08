from __future__ import absolute_import

import json, hashlib
from base64 import b64decode, b64encode
from custodia import log
from custodia.plugin import HTTPConsumer, HTTPError,  PluginOption
from custodia.secrets import Secrets

from custodia.plugin import (
    CSStoreDenied, CSStoreError, CSStoreExists, CSStoreUnsupported
)

from custodia.log import CustodiaLoggingAdapter, auditlog, getLogger

logger = getLogger(__name__)

DEFAULT_CTYPE = 'text/html; charset=utf-8'
SUPPORTED_COMMANDS = ['GET', 'PUT', 'POST', 'DELETE', 'HEAD']

class HeadHandler(HTTPConsumer):
    store = PluginOption('store', None, None)

    def __init__(self, config, section):
        super(HeadHandler, self).__init__(config, section)
        if self.store_name is not None:
            self.add_sub('secrets', HeadSecrets(config, section))

    def _find_handler(self, request):
        base = self
        command = request.get('command', 'GET')
        if command not in SUPPORTED_COMMANDS:
            raise HTTPError(501)
        trail = request.get('trail', None)
        if trail is not None:
            for comp in trail:
                subs = getattr(base, 'subs', {})
                if comp in subs:
                    base = subs[comp]
                    trail.pop(0)
                else:
                    break

        handler = getattr(base, command)
        if handler is None:
            raise HTTPError(400)

        return handler

class HeadSecrets(Secrets):
    def __init__(self, config, section):
        super(HeadSecrets, self).__init__(config, section)

    def HEAD(self, request, response):
        trail = request.get('trail', [])
        if len(trail) == 0 or trail[-1] == '':
            raise HTTPError(405)
        else:
            self._head_key(trail, request, response)

    def _head_key(self, trail, request, response):
        self._audit(log.AUDIT_GET_ALLOWED, log.AUDIT_GET_DENIED,
                    self._int_head_key, trail, request, response)

    def _int_head_key(self, trail, request, response):
        try:
            name = '/'.join(trail)
            handler = self._parse_query(request, name)
        except Exception as e:
            raise HTTPError(406, str(e))
        key = self._db_key(trail)
        try:
            content = b64decode(self.root.store.get(key))
            if content is None:
                raise HTTPError(404)
            elif len(content) == 0:
                raise HTTPError(406)
            output = handler.reply(None)
            response['output'] = output
            response['code'] = 200
            response['headers']['Content-Length'] = str(len(content))
            response['headers']['Content-MD5'] = b64encode(hashlib.md5(content).digest())
        except CSStoreDenied:
            self.logger.exception(
                "Get: Permission to perform this operation was denied")
            raise HTTPError(403)
        except CSStoreError:
            self.logger.exception('Get: Internal server error')
            raise HTTPError(500)
        except CSStoreUnsupported:
            self.logger.exception('Get: Unsupported operation')
            raise HTTPError(501)
