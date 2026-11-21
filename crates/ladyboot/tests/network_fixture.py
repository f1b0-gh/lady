"""Synthetic services inside the peer VM, on an isolated QEMU socketpair."""
import http.server
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading
import sys
from nts_peer import NtsPeer
import time

STATE = {'dns_enabled': True, 'ntp_enabled': True, 'dns_queries': 0,
         'ntp_queries': 0, 'plain_responses': 0, 'nts_ke_syn': 0, 'dhcp_requests': 0, 'udp_destinations': {}}
LOCK = threading.Lock()
STOP = threading.Event()
NTS = None


def snapshot():
    with LOCK:
        return json.loads(json.dumps(STATE))


def bump(key):
    with LOCK:
        STATE[key] += 1


def udp(port, callback, ready=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if port == 67:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'enp0s2\0')
    sock.bind(('0.0.0.0' if port == 67 else '192.0.2.1', port))
    sock.settimeout(1)
    if ready:
        print('LADYBOOT_PLAIN_READY', flush=True)
    while not STOP.is_set():
        try:
            data, address = sock.recvfrom(2048)
            callback(sock, data, address)
        except socket.timeout:
            pass
        except (ValueError, struct.error, IndexError) as error:
            print('FIXTURE_REJECTED_PACKET', type(error).__name__, flush=True)


def dhcp(sock, packet, _address):
    if len(packet) < 240 or packet[:3] != b'\x01\x01\x06' or packet[236:240] != b'\x63\x82\x53\x63':
        return
    options = {}
    offset = 240
    while offset < len(packet):
        tag = packet[offset]
        offset += 1
        if tag == 255:
            break
        if tag == 0:
            continue
        length = packet[offset]
        offset += 1
        if offset + length > len(packet):
            return
        options[tag] = packet[offset:offset + length]
        offset += length
    kind = options.get(53)
    if kind not in [b'\x01', b'\x03']:
        return
    bump('dhcp_requests')
    response = bytearray(packet[:240])
    response[0] = 2
    response[12:16] = b'\x00' * 4
    response[16:20] = socket.inet_aton('192.0.2.10')
    response[20:24] = socket.inet_aton('192.0.2.1')
    def option(tag, data):
        return bytes([tag, len(data)]) + data
    response += option(53, b'\x02' if kind == b'\x01' else b'\x05')
    response += option(54, socket.inet_aton('192.0.2.1'))
    response += option(51, struct.pack('!I', 3600))
    response += option(1, socket.inet_aton('255.255.255.0'))
    response += option(3, socket.inet_aton('192.0.2.254'))
    # Deliberately untrusted DHCP DNS/NTP, which production must ignore.
    response += option(6, socket.inet_aton('192.0.2.99'))
    response += option(42, socket.inet_aton('192.0.2.99')) + b'\xff'
    sock.sendto(response, ('255.255.255.255', 68))


def dns(sock, packet, address):
    if len(packet) < 17 or struct.unpack('!H', packet[4:6])[0] != 1:
        return
    bump('dns_queries')
    if not snapshot()['dns_enabled']:
        return
    offset = 12
    while packet[offset]:
        length = packet[offset]
        if length > 63 or offset + length + 1 >= len(packet):
            return
        offset += length + 1
    end = offset + 5
    if end > len(packet):
        return
    qtype, qclass = struct.unpack('!HH', packet[offset + 1:end])
    answer = qtype == 1 and qclass == 1
    response = packet[:2] + struct.pack('!HHHHH', 0x8180, 1, int(answer), 0, 0) + packet[12:end]
    if answer:
        response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton('192.0.2.2')
    sock.sendto(response, address)


def ntp(sock, packet, address):
    if len(packet) < 48:
        return
    bump('ntp_queries')
    if not snapshot()['ntp_enabled']:
        return
    response = bytearray(48)
    response[:4] = bytes([0x24, 1, 4, 0xec])
    response[12:16] = b'LOCL'
    response[24:32] = packet[40:48]
    seconds = time.time() + 2208988800
    timestamp = struct.pack('!II', int(seconds), int((seconds % 1) * 2**32))
    for offset in [16, 32, 40]:
        response[offset:offset + 8] = timestamp
    sock.sendto(response, address)


def observe():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind(('enp0s2', 0))
    sock.settimeout(1)
    while not STOP.is_set():
        try:
            packet = sock.recv(2048)
        except socket.timeout:
            continue
        if len(packet) < 42 or packet[12:14] != b'\x08\x00':
            continue
        source = socket.inet_ntoa(packet[26:30])
        destination = socket.inet_ntoa(packet[30:34])
        offset = 14 + (packet[14] & 15) * 4
        if offset < 34 or len(packet) < offset + 8:
            continue
        sport, port = struct.unpack('!HH', packet[offset:offset + 4])
        if packet[23] == 6 and len(packet) > offset + 13:
            if source == '192.0.2.10' and port == 4460 and packet[offset + 13] & 2:
                bump('nts_ke_syn')
            continue
        if packet[23] != 17:
            continue
        if source == '192.0.2.1' and destination == '192.0.2.10' and sport == 123:
            length = struct.unpack('!H', packet[offset + 4:offset + 6])[0]
            if length == 56:
                bump('plain_responses')
        if source != '192.0.2.10':
            continue
        if port == 123:
            bump('ntp_queries')
        if port in [53, 123, 124]:
            key = f'{destination}:{port}'
            with LOCK:
                if len(STATE['udp_destinations']) < 64 or key in STATE['udp_destinations']:
                    STATE['udp_destinations'][key] = STATE['udp_destinations'].get(key, 0) + 1


def ingress(source):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(4)
    sock.bind((source, 0))
    try:
        sock.connect(('192.0.2.10', 8080))
        sock.sendall(b'GET / HTTP/1.0\r\nHost: fixture\r\n\r\n')
        response = sock.recv(4096)
        return {'connected': True, 'http_ok': response.startswith((b'HTTP/1.0 200', b'HTTP/1.1 200'))}
    except OSError as error:
        return {'connected': False, 'error': type(error).__name__}
    finally:
        sock.close()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/nts/'):
            NTS.configure(self.path.removeprefix('/nts/'))
        if self.path == '/stop-dns':
            with LOCK:
                STATE['dns_enabled'] = False
        elif self.path == '/stop-ntp':
            with LOCK:
                STATE['ntp_enabled'] = False
        if self.path == '/ingress':
            result = [ingress(source) for source in ['192.0.2.3', '192.0.2.2', '192.0.2.3']]
        elif self.path == '/self-check':
            from network_probe import request
            for address, port in [('192.0.2.2', 443), ('192.0.2.3', 443), ('192.0.2.2', 444)]:
                assert request(address, port)['fixture'] == 'ladyboot-isolated-network'
            result = {'listeners_verified': True}
        else:
            result = {'fixture': 'ladyboot-isolated-network', **snapshot()}
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        if self.path == '/finish':
            print('LADYBOOT_PEER_RESULT ' + json.dumps(snapshot()), flush=True)
            subprocess.run(['systemctl', 'poweroff', '--no-block'], check=True, timeout=10)

    def log_message(self, format, *args):
        print('FIXTURE_HTTP ' + format % args, flush=True)


def main():
    global NTS
    subprocess.run(['ip', 'link', 'set', 'enp0s2', 'up'], check=True, timeout=10)
    for address in ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.254']:
        subprocess.run(['ip', 'addr', 'add', address + '/24', 'dev', 'enp0s2'], check=True, timeout=10)
    for port, callback in [(67, dhcp), (53, dns)]:
        threading.Thread(target=udp, args=(port, callback), daemon=True).start()
    threading.Thread(target=observe, daemon=True).start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/opt/qualification/net-cert.pem', '/opt/qualification/net-key.pem')
    for address, port in [('192.0.2.2', 443), ('192.0.2.3', 443), ('192.0.2.2', 444)]:
        server = http.server.ThreadingHTTPServer((address, port), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    NTS = NtsPeer()
    NTS.configure('valid')
    print('LADYBOOT_NETWORK_PEER_READY', flush=True)
    STOP.wait(1800)
    raise TimeoutError('peer exceeded its test budget')


if __name__ == '__main__':
    if sys.argv[1:] == ['--plain-ntp']:
        udp(123, ntp, ready=True)
    else:
        main()
