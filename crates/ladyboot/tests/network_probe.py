"""Small TLS/DNS probe shared by the disposable host and container tests."""
import argparse
import http.client
import json
import socket
import ssl


def request(host, port=443, path='/probe', ca='/opt/qualification/net-cert.pem', *, timeout=6):
    if not 0 < timeout <= 60:
        raise ValueError('fixture request timeout must be within 60 seconds')
    context = ssl.create_default_context(cafile=ca)
    connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    try:
        connection.request('GET', path, headers={'Connection': 'close'})
        response = connection.getresponse()
        body = response.read(65537)
        assert response.status == 200 and len(body) <= 65536
        return json.loads(body)
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ca', default='/opt/qualification/net-cert.pem')
    parser.add_argument('operation', choices=['dns', 'tls'])
    parser.add_argument('host')
    parser.add_argument('port', nargs='?', type=int, default=443)
    parser.add_argument('path', nargs='?', default='/probe')
    args = parser.parse_args()
    if args.operation == 'dns':
        result = sorted({row[4][0] for row in socket.getaddrinfo(args.host, None, socket.AF_INET)})
    else:
        result = request(args.host, args.port, args.path, args.ca)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
