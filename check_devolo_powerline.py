#!/usr/bin/env python3

import argparse
import json
import logging
import re
import uuid
from math import floor
from datetime import timedelta

import requests
import nagiosplugin

_log = logging.getLogger('nagiosplugin')

# 6 days, 15h 28m 59s
UPTIME_FMT = re.compile(
        r'(?P<days>\d+) days, ' +
        r'(?P<hours>\d+)h (?P<minutes>\d+)m (?P<seconds>\d+)s')


class LegacyDevolo(nagiosplugin.Resource):
    def __init__(self, host, remote_mac=None):
        self._endpoint = "http://%s/assets/data.cfl" % host
        self._remote_mac = remote_mac

    def probe(self):
        data = self.fetch_data()

        matcher = UPTIME_FMT.match(data['SYSTEM.GENERAL.UPTIME'])
        if matcher is not None:
            uptime = timedelta(
                    **{k: int(v) for k, v in matcher.groupdict().items()})
            yield nagiosplugin.Metric(
                    'uptime', int(uptime.total_seconds()), uom='s',
                    min=0, context='uptime')

        yield nagiosplugin.Metric(
                'cpu', int(data['SYSTEM.STATS.CPU_USAGE']), uom='%', min=0,
                max=100, context='load')
        yield nagiosplugin.Metric(
                'memory',
                int(data['SYSTEM.STATS.TOTAL_MEMORY']) -
                int(data['SYSTEM.STATS.FREE_MEMORY']),
                uom='MB', min=0, max=int(data['SYSTEM.STATS.TOTAL_MEMORY']),
                context='memory')

        thresholds = list(map(int,
                              data['MSPS.INTERNAL.THRESHOLDS'].split(',')))
        yield nagiosplugin.Metric(
                'temp', int(data['TEMPSENSORS.GENERAL.MEASURE']) / 100,
                uom='degree', contextobj=nagiosplugin.ScalarContext(
                    'temperature', warning=thresholds[3]/100,
                    critical=thresholds[0]/100))

        devices = zip(
                data['DIDMNG.GENERAL.DIDS'].split(','),
                data['DIDMNG.GENERAL.MACS'].split(','),
                data['DIDMNG.GENERAL.RX_BPS'].split(','),
                data['DIDMNG.GENERAL.TX_BPS'].split(','))
        for did, mac, rx_bps, tx_bps in devices:
            if did == '0' or did == data['NODE.GENERAL.DEVICE_ID']:
                continue
            yield nagiosplugin.Metric(
                    'rx-%s' % did,
                    floor(32 * int(rx_bps) / 1000 * .75 / .45), uom='Mbps',
                    min=0, context='dlan')
            yield nagiosplugin.Metric(
                    'tx-%s' % did,
                    floor(32 * int(tx_bps) / 1000 * .75 / .45), uom='Mbps',
                    min=0, context='dlan')

    def fetch_data(self):
        _log.info("Fetching data")
        data = {}
        result = requests.get(self._endpoint)
        for line in result.text.splitlines():
            if "=" in line:
                _log.debug(line)
                k, v = line.split("=")
                data[k] = v
        return data


class Devolo(nagiosplugin.Resource):
    def __init__(self, host, remote_mac, username="root", password=""):
        self._endpoint = 'http://%s/ubus' % host
        self._remote_mac = remote_mac
        self._session_id = None
        self._username = username
        self._password = password

    def probe(self):
        sysinfo = self.system_info()
        yield nagiosplugin.Metric(
                'uptime', sysinfo['uptime'], uom='s', min=0, context='uptime')
        for n, load in zip([1, 5, 15], sysinfo['load']):
            yield nagiosplugin.Metric(
                    'load%i' % n, load / 65535, min=0, context='load')

        yield nagiosplugin.Metric(
                'mem', sysinfo['memory']['total'] - sysinfo['memory']['free'],
                uom='B', min=0, max=sysinfo['memory']['total'],
                context='memory')

        ghninfo = self.ghninfo()
        for device in ghninfo['devices']:
            if device['did'] == ghninfo['device_id']:
                continue

            if self._remote_mac is None or \
                    self._remote_mac.to_lower() == device['mac'].to_lower():
                yield nagiosplugin.Metric(
                        "rx-%s" % device['did'], int(device['rx']), uom='Mbps',
                        min=0, context='dlan')
                yield nagiosplugin.Metric(
                        "tx-%s" % device['did'], int(device['tx']), uom='Mbps',
                        min=0, context='dlan')

        connected_clients = [
                client
                for device in self.devices()
                if device.startswith('ath')
                for client in self.clients(device)]
        yield nagiosplugin.Metric(
                'devices', len(connected_clients), min=0, context='devices')

    def call(self, group, method, **kwargs):
        _log.info("Calling %s.%s(%s)" % (group, method, kwargs))
        payload = {
            "id": str(uuid.uuid4()),
            "jsonrpc": "2.0",
            "method": "call",
            "params": [self._get_session_id(), group, method, kwargs]
        }
        resp = requests.post(self._endpoint, json=payload).json()
        if resp['result'][0] != 0:
            _log.fatal('Received error code %s' % resp['result'])
            raise RuntimeError('Error calling %s.%s' % (group, method))
        _log.debug("Received response: %s" % resp)
        return resp['result'][1]

    def _get_session_id(self):
        if self._session_id is None:
            _log.debug("No session ID, logging in")
            self._session_id = "00000000000000000000000000000000"
            login_info = self.call(
                    "session", "login", username=self._username,
                    password=self._password, timeout=900)
            self._session_id = login_info["ubus_rpc_session"]
            _log.debug("Got session ID %s" % self._session_id)
        return self._session_id

    def ghninfo(self):
        """
            {'device_id': '2',
             'devices': [
                {'did': '1',
                 'mac': 'B8:BE:F4:66:25:7B',
                 'rx': '519',
                 'tx': '507',
                 'role': 'DOMAIN_MASTER'},
                {'did': '2',
                 'mac': 'B8:BE:F4:64:5E:DC',
                 'role': 'END_POINT'}]}
        """
        return self.call("network.ghntool", "ghninfo")

    def radio_state(self):
        """
            {'wifi0':
                {'frequency': 2412,
                 'channel': 1,
                 'ssid': 'OphetEi',
                 'config':
                    {'_anonymous': False,
                     '_type': 'wifi-device',
                     '_name': 'wifi0',
                     'channel': 'auto',
                     'txpower': '20',
                     'htmode': 'HT40',
                     'hwmode': '11g',
                     'autorescan': '1',
                     'autorescan_interval': '120',
                     'set_fw_recovery': '1',
                     'atfstrictsched': '0',
                     'atfobsssched': '1',
                     'type': 'qcawificfg80211',
                     'preamble': '1',
                     'country': 'CH',
                     'disabled': '0',
                     'cfg_disabled': '0',
                     'supported_rates': ['54000', '48000', ..., '1000'],
                     'basic_rate': ['11000', '5500', '2000', '1000']}},
             'wifi1':
                {'frequency': 5600,
                 'channel': 120,
                 'ssid': 'OphetEi',
                 'config': {...},
                 }}
        """
        return self.call("network.info", "radio_state")

    def devices(self):
        """
            {'devices': ['wifi0', 'wifi1', 'ath0', 'ath1']}
        """
        return self.call("iwinfo", "devices")['devices']

    def clients(self, device):
        """
            {'clients':
                {'E0:AC:CB:9C:62:5A':
                    {'connected_time': 156,
                     'vendor': {'name': 'Apple', 'description': 'Apple, Inc.'},
                     'rx': {'rate': 5000},
                     'tx': {'rate': 2000},
                     'ipaddr': '192.168.1.22'},
                 'F8:D0:27:D1:3B:0E':
                    {'connected_time': 523919,
                     'vendor':
                        {'name': 'SeikoEps',
                         'description': 'Seiko Epson Corporation'},
                     'rx': {'rate': 72000},
                     'tx': {'rate': 72000},
                     'ipaddr': '192.168.1.29'}}}
        """
        return self.call("network.info", "clients", device=device)['clients']

    def system_info(self):
        """
            {'uptime': 522558,
             'localtime': 1597311514,
             'load': [29024, 24576, 19744],
             'memory':
                {'total': 253546496,
                 'free': 83570688,
                 'shared': 278528,
                 'buffered': 13393920},
             'swap': {'total': 0, 'free': 0}}
        """
        return self.call("system", "info")


@nagiosplugin.guarded
def main():
    argp = argparse.ArgumentParser()
    argp.add_argument('-H', '--host', required=True,
                      help='IP address of powerline adapter to check')
    argp.add_argument('-r', '--remote_mac',
                      help='MAC address of remote DLAN adapter')
    argp.add_argument('-l', '--legacy', action='store_true', default=False)
    argp.add_argument('-v', '--verbose', action='count', default=0)
    args = argp.parse_args()
    resource_cls = LegacyDevolo if args.legacy else Devolo
    resource = resource_cls(args.host, args.remote_mac)
    check = nagiosplugin.Check(
            resource,
            nagiosplugin.ScalarContext('dlan'),
            nagiosplugin.ScalarContext('uptime'),
            nagiosplugin.ScalarContext('load'),
            nagiosplugin.ScalarContext('temp'),
            nagiosplugin.ScalarContext('devices'),
            nagiosplugin.ScalarContext('memory'))
    check.name = 'dlan'
    check.main(args.verbose)


if __name__ == '__main__':
    main()
