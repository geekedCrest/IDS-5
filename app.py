# -*- coding: utf-8 -*-
import random
import time
import threading
import json
import os
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from rules import load_rules, verify_rules
from signature import Signature

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-dashboard-secret'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')

# ─── State ────────────────────────────────────────────────────────────────────

state = {
    'running': False,
    'paused': False,
    'packet_count': 0,
    'alert_count': 0,
    'filtered_count': 0,
    'interface': 'eth0 (simulated)',
    'start_time': None,
    'rules': [],
    'packets': [],
    'alerts': [],
    'protocol_stats': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'DNS': 0, 'OTHER': 0},
    'traffic_history': [],
    'active_filter': '',
}

PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'ARP', 'TLS', 'SSH', 'FTP', 'SMTP']
THREAT_LEVELS = ['LOW', 'LOW', 'LOW', 'LOW', 'MEDIUM', 'MEDIUM', 'HIGH', 'CRITICAL']

SAMPLE_IPS = [
    '192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.178.22',
    '10.0.0.1', '10.0.0.5', '172.16.0.1', '1.1.1.1', '8.8.8.8',
    '127.0.0.1', '0.0.0.0', '255.255.255.255', '192.0.0.1',
    '185.220.101.5', '45.33.32.156', '198.51.100.1', '203.0.113.50',
]

COMMON_PORTS = [80, 443, 22, 21, 25, 53, 8080, 8443, 3306, 5432,
                1234, 12345, 501, 8000, 65535, 1235]

ATTACK_TYPES = ['Port Scan', 'DoS Attack', 'Brute Force', 'SQL Injection',
                'XSS Attempt', 'ARP Spoofing', 'DNS Poisoning', 'MITM']

INFO_TEMPLATES = {
    'TCP': ['SYN', 'ACK', 'FIN', 'RST', 'PSH,ACK', 'SYN,ACK', 'Seq={seq} Ack={ack} Win={win}'],
    'UDP': ['Src Port: {sport} Dst Port: {dport}', 'DNS Standard query', 'DHCP Discover'],
    'ICMP': ['Echo (ping) request  id={id}, seq={seq}', 'Echo (ping) reply id={id}, seq={seq}', 'Destination unreachable'],
    'HTTP': ['GET / HTTP/1.1', 'POST /api/data HTTP/1.1', 'HTTP/1.1 200 OK', 'HTTP/1.1 404 Not Found'],
    'DNS': ['Standard query 0x{id:04x} A {domain}', 'Standard query response A {ip}'],
    'ARP': ['Who has {ip}? Tell {src}', 'Reply {ip} is-at {mac}'],
    'TLS': ['Client Hello', 'Server Hello', 'Application Data', 'Certificate'],
    'SSH': ['Client: Protocol exchange', 'Server: Key Exchange Init', 'New Keys'],
    'FTP': ['Request: USER anonymous', 'Response: 220 FTP server ready', 'Request: RETR file.txt'],
    'SMTP': ['EHLO mail.example.com', 'MAIL FROM:<sender@example.com>', 'DATA'],
}

DOMAINS = ['google.com', 'example.com', 'cloudflare.com', 'github.com',
           'evil-domain.ru', 'malware-c2.net', 'suspicious-host.xyz']
MACS = ['aa:bb:cc:dd:ee:ff', '00:11:22:33:44:55', 'de:ad:be:ef:00:01']

# ─── Load rules ────────────────────────────────────────────────────────────────

def load_ids_rules(path='default.rules'):
    try:
        rules = load_rules(path)
        state['rules'] = [str(r) for r in rules]
        return rules
    except ValueError as e:
        print(f'[WARN] Could not load rules from {path}: {e}')
        return []

ids_rules = load_ids_rules('default.rules')

# ─── Packet simulation ─────────────────────────────────────────────────────────

def _fmt_info(proto):
    tpl = random.choice(INFO_TEMPLATES.get(proto, ['Data transfer']))
    return tpl.format(
        seq=random.randint(1000, 9999999),
        ack=random.randint(1000, 9999999),
        win=random.choice([65535, 8192, 29200, 1024]),
        sport=random.choice(COMMON_PORTS),
        dport=random.choice(COMMON_PORTS),
        id=random.randint(0, 0xFFFF),
        ip=random.choice(SAMPLE_IPS),
        src=random.choice(SAMPLE_IPS),
        mac=random.choice(MACS),
        domain=random.choice(DOMAINS),
    )

def _generate_packet():
    proto = random.choices(
        PROTOCOLS,
        weights=[30, 20, 10, 15, 10, 3, 5, 3, 2, 2]
    )[0]

    # Occasionally generate packets that will match rules
    trigger_rule = random.random() < 0.12 and ids_rules

    if trigger_rule:
        rule = random.choice(ids_rules)
        src_ip = rule.src_ip if rule.src_ip not in ('any',) and '!' not in rule.src_ip else random.choice(SAMPLE_IPS)
        dst_ip = rule.dst_ip if rule.dst_ip not in ('any',) and '!' not in rule.dst_ip else random.choice(SAMPLE_IPS)
        proto = rule.proto if rule.proto not in ('any', 'IP') else proto
        src_port = rule.src_port if rule.src_port not in ('any',) and '!' not in rule.src_port and '[' not in rule.src_port else str(random.choice(COMMON_PORTS))
        dst_port = rule.dst_port if rule.dst_port not in ('any',) and '!' not in rule.dst_port and '[' not in rule.dst_port else str(random.choice(COMMON_PORTS))
    else:
        src_ip = random.choice(SAMPLE_IPS)
        dst_ip = random.choice(SAMPLE_IPS)
        src_port = random.choice(COMMON_PORTS)
        dst_port = random.choice(COMMON_PORTS)

    length = random.randint(40, 1500)
    state['packet_count'] += 1
    pkt_id = state['packet_count']
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]

    # Check against rules
    is_alert = False
    matched_rule = None
    for rule in ids_rules:
        r_src_ip = src_ip
        r_dst_ip = dst_ip
        r_src_port = str(src_port)
        r_dst_port = str(dst_port)
        r_proto = proto
        if (rule.src_ip in ('any', r_src_ip) and
            rule.dst_ip in ('any', r_dst_ip) and
            rule.proto in ('any', 'IP', r_proto)):
            is_alert = True
            matched_rule = str(rule)
            break

    threat = 'CRITICAL' if is_alert else random.choices(
        ['LOW', 'LOW', 'LOW', 'MEDIUM', 'HIGH'],
        weights=[60, 10, 10, 15, 5]
    )[0]

    hex_bytes = ' '.join(f'{random.randint(0,255):02x}' for _ in range(min(length, 64)))
    hex_lines = []
    raw = bytes(random.randint(0, 255) for _ in range(min(length, 64)))
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        hex_lines.append({'offset': f'{i:04x}', 'hex': hex_part, 'ascii': ascii_part})

    layers = _build_layers(proto, src_ip, dst_ip, str(src_port), str(dst_port), length)

    pkt = {
        'id': pkt_id,
        'ts': ts,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'proto': proto,
        'length': length,
        'info': _fmt_info(proto),
        'threat': threat,
        'is_alert': is_alert,
        'matched_rule': matched_rule,
        'hex': hex_lines,
        'layers': layers,
    }

    # Update protocol stats
    proto_key = proto if proto in state['protocol_stats'] else 'OTHER'
    state['protocol_stats'][proto_key] = state['protocol_stats'].get(proto_key, 0) + 1

    return pkt

def _build_layers(proto, src_ip, dst_ip, src_port, dst_port, length):
    layers = [
        {
            'name': f'Frame {state["packet_count"]}: {length} bytes on wire',
            'fields': [
                {'key': 'Encapsulation type', 'value': 'Ethernet (1)'},
                {'key': 'Frame Length', 'value': f'{length} bytes'},
                {'key': 'Capture Length', 'value': f'{length} bytes'},
            ],
        },
        {
            'name': f'Ethernet II, Src: {random.choice(MACS)}, Dst: {random.choice(MACS)}',
            'fields': [
                {'key': 'Destination', 'value': random.choice(MACS)},
                {'key': 'Source', 'value': random.choice(MACS)},
                {'key': 'Type', 'value': '0x0800 (IPv4)' if proto != 'ARP' else '0x0806 (ARP)'},
            ],
        },
        {
            'name': f'Internet Protocol Version 4, Src: {src_ip}, Dst: {dst_ip}',
            'fields': [
                {'key': 'Version', 'value': '4'},
                {'key': 'Header Length', 'value': '20 bytes'},
                {'key': 'Total Length', 'value': str(length)},
                {'key': 'TTL', 'value': str(random.choice([64, 128, 255]))},
                {'key': 'Source Address', 'value': src_ip},
                {'key': 'Destination Address', 'value': dst_ip},
            ],
        },
    ]

    if proto in ('TCP', 'HTTP', 'TLS', 'SSH', 'FTP', 'SMTP'):
        layers.append({
            'name': f'Transmission Control Protocol, Src Port: {src_port}, Dst Port: {dst_port}',
            'fields': [
                {'key': 'Source Port', 'value': src_port},
                {'key': 'Destination Port', 'value': dst_port},
                {'key': 'Sequence Number', 'value': str(random.randint(0, 4294967295))},
                {'key': 'Acknowledgment Number', 'value': str(random.randint(0, 4294967295))},
                {'key': 'Flags', 'value': random.choice(['0x002 (SYN)', '0x010 (ACK)', '0x018 (PSH,ACK)', '0x001 (FIN)'])},
                {'key': 'Window Size', 'value': str(random.choice([65535, 8192, 29200]))},
            ],
        })
    elif proto in ('UDP', 'DNS'):
        layers.append({
            'name': f'User Datagram Protocol, Src Port: {src_port}, Dst Port: {dst_port}',
            'fields': [
                {'key': 'Source Port', 'value': src_port},
                {'key': 'Destination Port', 'value': dst_port},
                {'key': 'Length', 'value': str(length - 20)},
                {'key': 'Checksum', 'value': f'0x{random.randint(0, 0xFFFF):04x}'},
            ],
        })
    elif proto == 'ICMP':
        layers.append({
            'name': 'Internet Control Message Protocol',
            'fields': [
                {'key': 'Type', 'value': random.choice(['8 (Echo request)', '0 (Echo reply)', '3 (Destination unreachable)'])},
                {'key': 'Code', 'value': '0'},
                {'key': 'Checksum', 'value': f'0x{random.randint(0, 0xFFFF):04x}'},
                {'key': 'Identifier', 'value': str(random.randint(1, 65535))},
                {'key': 'Sequence Number', 'value': str(random.randint(1, 1000))},
            ],
        })

    if proto in ('HTTP',):
        layers.append({
            'name': 'Hypertext Transfer Protocol',
            'fields': [
                {'key': 'Method', 'value': random.choice(['GET', 'POST', 'PUT', 'DELETE'])},
                {'key': 'URI', 'value': random.choice(['/', '/api/data', '/login', '/admin'])},
                {'key': 'Host', 'value': random.choice(DOMAINS)},
                {'key': 'User-Agent', 'value': 'Mozilla/5.0 (compatible; Scanner/1.0)'},
            ],
        })

    return layers


def _check_for_attacks(packets_window):
    """Detect simple attack patterns in a window of recent packets."""
    alerts = []
    src_count = {}
    dst_count = {}
    dst_port_count = {}

    for p in packets_window:
        src = p['src_ip']
        dst = p['dst_ip']
        dport = p.get('dst_port', 0)
        src_count[src] = src_count.get(src, 0) + 1
        dst_count[dst] = dst_count.get(dst, 0) + 1
        key = f'{src}->{dst}'
        dst_port_count[key] = dst_port_count.get(key, 0) + 1

    for src, cnt in src_count.items():
        if cnt > 20:
            alerts.append({
                'type': 'DoS Attack',
                'threat': 'CRITICAL',
                'src': src,
                'dst': 'multiple',
                'ts': datetime.now().strftime('%H:%M:%S'),
                'detail': f'{cnt} packets from {src} in last window',
            })
    return alerts


# ─── Background simulation thread ──────────────────────────────────────────────

def simulation_thread():
    recent_packets = []
    traffic_tick = 0
    while True:
        if state['running'] and not state['paused']:
            delay = random.uniform(0.05, 0.35)
            time.sleep(delay)

            pkt = _generate_packet()
            state['packets'].append(pkt)
            if len(state['packets']) > 2000:
                state['packets'] = state['packets'][-2000:]
            recent_packets.append(pkt)
            if len(recent_packets) > 100:
                recent_packets = recent_packets[-100:]

            socketio.emit('packet', pkt)

            if pkt['is_alert']:
                alert = {
                    'id': state['alert_count'] + 1,
                    'ts': pkt['ts'],
                    'type': random.choice(ATTACK_TYPES),
                    'threat': pkt['threat'],
                    'src': pkt['src_ip'],
                    'dst': pkt['dst_ip'],
                    'rule': pkt['matched_rule'],
                    'info': pkt['info'],
                    'proto': pkt['proto'],
                }
                state['alert_count'] += 1
                state['alerts'].append(alert)
                if len(state['alerts']) > 500:
                    state['alerts'] = state['alerts'][-500:]
                socketio.emit('alert', alert)

            traffic_tick += 1
            if traffic_tick % 20 == 0:
                attack_alerts = _check_for_attacks(recent_packets)
                for al in attack_alerts:
                    state['alert_count'] += 1
                    al['id'] = state['alert_count']
                    state['alerts'].append(al)
                    socketio.emit('alert', al)

                traffic_point = {
                    'ts': datetime.now().strftime('%H:%M:%S'),
                    'pps': round(1 / delay, 1),
                    'total': state['packet_count'],
                }
                state['traffic_history'].append(traffic_point)
                if len(state['traffic_history']) > 60:
                    state['traffic_history'] = state['traffic_history'][-60:]
                socketio.emit('traffic_update', {
                    'traffic': traffic_point,
                    'protocol_stats': state['protocol_stats'],
                    'status': _status(),
                })
        else:
            time.sleep(0.2)


def _status():
    return {
        'packet_count': state['packet_count'],
        'alert_count': state['alert_count'],
        'filtered_count': state['filtered_count'],
        'interface': state['interface'],
        'running': state['running'],
        'paused': state['paused'],
        'uptime': _uptime(),
    }


def _uptime():
    if state['start_time']:
        elapsed = int(time.time() - state['start_time'])
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        return f'{h:02d}:{m:02d}:{s:02d}'
    return '00:00:00'


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    return jsonify(_status())


@app.route('/api/packets')
def api_packets():
    limit = int(request.args.get('limit', 200))
    return jsonify(state['packets'][-limit:])


@app.route('/api/alerts')
def api_alerts():
    return jsonify(state['alerts'][-100:])


@app.route('/api/rules')
def api_rules():
    rules = []
    for path in ['default.rules', 'eval.rules']:
        if os.path.exists(path):
            with open(path) as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    rules.append({
                        'line': i,
                        'file': path,
                        'text': line,
                        'is_comment': line.startswith('#'),
                        'is_empty': line == '',
                    })
    return jsonify(rules)


@app.route('/api/rules/validate', methods=['POST'])
def api_validate_rule():
    data = request.json or {}
    rule_text = data.get('rule', '').strip()
    if not rule_text:
        return jsonify({'valid': False, 'error': 'Empty rule'})
    try:
        sigs = verify_rules([rule_text])
        return jsonify({'valid': True, 'parsed': str(sigs[0])})
    except ValueError as e:
        return jsonify({'valid': False, 'error': str(e)})


@app.route('/api/stats')
def api_stats():
    return jsonify({
        'protocol_stats': state['protocol_stats'],
        'traffic_history': state['traffic_history'][-30:],
        'status': _status(),
    })


# ─── WebSocket events ─────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    emit('init', {
        'status': _status(),
        'protocol_stats': state['protocol_stats'],
        'rules': state['rules'],
        'recent_packets': state['packets'][-50:],
        'recent_alerts': state['alerts'][-20:],
        'traffic_history': state['traffic_history'][-30:],
    })


@socketio.on('start_capture')
def on_start():
    state['running'] = True
    state['paused'] = False
    if not state['start_time']:
        state['start_time'] = time.time()
    emit('status_update', _status(), broadcast=True)


@socketio.on('stop_capture')
def on_stop():
    state['running'] = False
    state['paused'] = False
    emit('status_update', _status(), broadcast=True)


@socketio.on('pause_capture')
def on_pause():
    state['paused'] = not state['paused']
    emit('status_update', _status(), broadcast=True)


@socketio.on('restart_capture')
def on_restart():
    state['running'] = False
    state['paused'] = False
    state['packet_count'] = 0
    state['alert_count'] = 0
    state['filtered_count'] = 0
    state['packets'] = []
    state['alerts'] = []
    state['protocol_stats'] = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'DNS': 0, 'OTHER': 0}
    state['traffic_history'] = []
    state['start_time'] = None
    emit('cleared', {}, broadcast=True)
    time.sleep(0.3)
    state['running'] = True
    state['start_time'] = time.time()
    emit('status_update', _status(), broadcast=True)


@socketio.on('set_filter')
def on_set_filter(data):
    state['active_filter'] = data.get('filter', '')
    emit('filter_applied', {'filter': state['active_filter']}, broadcast=True)


@socketio.on('load_rules')
def on_load_rules(data):
    global ids_rules
    path = data.get('path', 'default.rules')
    ids_rules = load_ids_rules(path)
    emit('rules_loaded', {'rules': state['rules'], 'count': len(ids_rules)}, broadcast=True)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    t = threading.Thread(target=simulation_thread, daemon=True)
    t.start()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
