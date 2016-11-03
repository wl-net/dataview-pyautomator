#!/usr/bin/env python3
import sys
assert sys.version >= '3.3', 'Please use Python 3.3 or higher.'

import argparse
import os
import ssl
import hashlib
import binascii
import requests
import json


import asyncio
import aiohttp
import aiohttp.server


def constant_time_equals(val1, val2):
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0


class X509Certificate(object):
    def __init__(self, filename=None):
        self.filename = filename

    @classmethod
    def __current_dir(cls):
        return os.path.dirname(os.path.realpath(__file__))

    @classmethod
    def create_from_str(cls, str):
        filename = cls.__current_dir() + '/' + hashlib.sha256(str.encode('utf-8')).hexdigest() + '.pem'

        with open(filename, 'w') as f:
            f.write(str)

        return X509Certificate(filename)

    @classmethod
    def get_file_from_str(cls, str):
        filename = cls.__current_dir() + '/' + hashlib.sha256(str.encode('utf-8')).hexdigest() + '.pem'
        if not os.path.exists(filename):
            raise ValueError('Certificate does not exist')

        return filename

    def get_location(self):
        if not self.filename:
            raise ValueError('Certificate does not exist')

        return self.filename


class JSONRPCClient(object):
    def __init__(self):
        self.request_id = 1
        self.target = None
        self.apikey = None
        self.certificate = None

    def connect(self, target, apikey, certificate=None):
        self.target = target
        self.apikey = apikey
        self.certificate = certificate

    def disconnect(self):
        pass # this transport does not stay open

    def call(self, command, arguments):
        req = {'jsonrpc': '2.0', 'method': command, 'params': arguments, 'id': self.request_id}
        self.request_id += 1

        if self.certificate:
            try:
                cert_file = X509Certificate.get_file_from_str(self.certificate)
            except ValueError:
                cert_file = X509Certificate.create_from_str(self.certificate).get_location()

            request = requests.post(self.target, data=json.dumps(req),
                              headers={'Authorization': 'Token ' + self.apikey},
                              verify=cert_file)
        else:
            request = requests.post(self.target, data=json.dumps(req),
                              headers={'Authorization': 'Token: ' + self.apikey})

        if request.status_code == 200:
            return request.json()['result']

        request.raise_for_status()

    @classmethod
    def generate_random_token(cls):
        """
        generates a token suitable for authentication
        :return:
        """
        return binascii.hexlify(os.urandom(32)).decode('utf-8')

    def get_client(self):
        return self.client

    def healthcheck(self):
        pass


class DataviewRPCServer(aiohttp.server.ServerHttpProtocol):
    class InsufficientTokenLength(Exception):
        pass

    def __init__(self, dispatch_functions, auth_token):
        self.dispatch_functions = dispatch_functions
        self.auth_token = auth_token
        if len(auth_token) < 32:
            raise DataviewRPCServer.InsufficentTokenLength('auth_token is insufficiently long')

        super().__init__()

    @asyncio.coroutine
    def handle_request(self, message, payload):
        print('method = {!r}; path = {!r}; version = {!r}'.format(
        message.method, message.path, message.version))

        if message.method == 'POST' and message.path == '/rpc':
            if not 'Authorization' in message.headers:
                response = aiohttp.Response(
                    self.writer, 401, http_version=message.version
                )
                response.add_header('Content-Length', '0')
                response.add_header('WWW-Authenticate', 'Token')
                response.send_headers()
                return

            authorization = message.headers.get('Authorization').split(' ')
            if authorization[0] != 'Token' or not constant_time_equals(authorization[1], self.auth_token):
                response = aiohttp.Response(
                    self.writer, 403, http_version=message.version
                )
                response.add_header('Content-Length', '0')
                response.send_headers()
                return

            # authorization passed, process the request.
            data = yield from payload.read()
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )

            result = self.process_request(data)
            response.add_header('Content-Length', str(len(result)))
            response.send_headers()

            response.write(result)
        else:
            response = aiohttp.Response(
                self.writer, 405, http_version=message.version
            )
            response.add_header('Accept', 'POST')
            response.send_headers()

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport
        super().connection_made(transport)

    def process_request(self, data):
        response = {}
        message = data.decode()

        try:
            payload = json.loads(message)
        except ValueError:
            response = {'jsonrpc': '2.0', 'error': {'code': -32700, 'message': 'Parse error'}, 'id': None}
            return str.encode(json.dumps(response) + '\n')

        try:
            if payload['jsonrpc'] != '2.0':
                response = {'jsonrpc': '2.0', 'error': {'code': -32600, 'message': 'Invalid Request'}, 'id': None}
                return str.encode(json.dumps(response) + '\n')
            response['jsonrpc'] = '2.0'
            response['id'] = payload['id']
        except KeyError:
            response = {}

        if 'method' in payload:
            if payload['method'] not in self.dispatch_functions:
                  response = {'jsonrpc': '2.0',
                              'error': {'code': -32601, 'message': 'Method not found'},
                              'id': payload['id']}
                  return str.encode(json.dumps(response) + '\n')
            # TODO handle missing method

        if 'params' not in payload:
            response['result'] = self.dispatch_functions[payload['method']]()

        elif type(payload['params']) is dict:
            response['result'] = self.dispatch_functions[payload['method']](**payload['params'])
        else:
            response['result'] = self.dispatch_functions[payload['method']](*payload['params'])

        return str.encode(json.dumps(response) + '\n')


class BaseController(object):
    def get_mapping(self):
        return {'health': lambda: self.health()}

    def health(self):
        return "OK"


def prompt(controller):
    ARGS = argparse.ArgumentParser(description='Run automator')
    ARGS.add_argument(
        '--host', action='store', dest='host',
        default='localhost', help='Host name')
    ARGS.add_argument(
        '--port', action='store', dest='port',
        default=8080, type=int, help='Port number')
    ARGS.add_argument(
        '--tlscert', action='store', dest='certfile', help='TLS X.509 certificate file.')
    ARGS.add_argument(
        '--tlskey', action='store', dest='keyfile', help='TLS key file.')
    args = ARGS.parse_args()

    if ':' in args.host:
        args.host, port = args.host.split(':', 1)
        args.port = int(port)

    start(controller, args.certfile, args.keyfile, args.host, args.port)


def start(controller, cert, key, host, port, unit_test=False):
    if sys.version >= '3.4':
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    else:
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

    sslcontext.load_cert_chain(cert, key)

    loop = asyncio.get_event_loop()

    server = loop.create_server(
        lambda: DataviewRPCServer(
          controller.get_mapping(), os.environ.get('RPCSERVER_TOKEN')
        ),
        host, port,
        ssl=sslcontext)
    svr = loop.run_until_complete(server)
    socks = svr.sockets
    print('Server started. Waiting for connections on ', socks[0].getsockname())
    if unit_test:
        print('Entering unit test mode..')
        def loop_in_thread(loop):
            #asyncio.set_event_loop(loop)
            print("background...")
            loop.run_forever()
            print("DONEs")

        #loop = asyncio.get_event_loop()
        import threading
        t = threading.Thread(target=loop_in_thread, args=(loop,))
        t.start()
        return loop
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    start(BaseController(), '../cert.pem', '../server.pem', '0.0.0.0', 6000)

