import hashlib
import os

import redis
import configparser


class ArpTable:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('configs/redis.ini')
        redis_host = config.get("arp_table", "host")
        redis_port = config.get("arp_table", "port")
        redis_pass = config.get("arp_table", "password", fallback=None)
        redis_db = config.get("arp_table", "database", fallback=1)
        self._redis_conn = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db,
                                             password=redis_pass)

    def add_record(self, net, mac, ip):
        net_hsh = hashlib.md5(net.encode()).hexdigest()
        self._redis_conn.set("%s_%s" % (net_hsh, ip), mac)

    def get_record(self, net, ip):
        net_hsh = hashlib.md5(net.encode()).hexdigest()
        result = self._redis_conn.get("%s_%s" % (net_hsh, ip))
        if result is not None:
            result = result.decode("utf-8")
        return result

    def __del__(self):
        self._redis_conn.close()