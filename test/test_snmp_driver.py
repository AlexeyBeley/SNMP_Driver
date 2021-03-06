import os
import time
import pdb
import sys
import datetime

sys.path.insert(0, "..")

from src.snmp_driver import SnmpDriver


def test_sub(self, str_address, lst_oids):
    print(str(lst_oids))
    ret = self.execute(str_address, lst_oids)
    print(str(ret))


# snmpget -mALL -v2c -c incap424 172.31.2.2 1.3.6.1.2.1.15.3.1.2.192.168.15.2
# snmpget -mALL -v2c -c incap424 172.31.1.106 1.3.6.1.2.1.15.3.1.2.10.100.6.30
def test():
    # pdb.set_trace()
    self = SnmpDriver(SnmpDriver.OperationMode.SINGLE_THREAD)
    self.start()
    #for x in range(100):
    #    time.sleep(1)
    #return
    # str_address='172.31.1.106'
    str_address = '172.31.2.2'
    lst_oids = ['1.3.6.1.2.1.15.3.1.2.10.6.1.5', '1.3.6.1.2.1.15.3.1.2.10.6.1.13', '1.3.6.1.2.1.15.3.1.2.10.5.0.5',
                '1.3.6.1.2.1.15.3.1.2.10.5.0.13', '1.3.6.1.2.1.15.3.1.2.10.5.0.21', '1.3.6.1.2.1.15.3.1.2.10.5.0.29',
                '1.3.6.1.2.1.15.3.1.2.10.5.0.37', '1.3.6.1.2.1.15.3.1.2.10.5.0.45', '1.3.6.1.2.1.15.3.1.2.10.5.0.53',
                '1.3.6.1.2.1.15.3.1.2.10.5.0.61', '1.3.6.1.2.1.15.3.1.2.10.5.0.69', '1.3.6.1.2.1.15.3.1.2.10.5.0.77',
                '1.3.6.1.2.1.15.3.1.2.10.5.0.85', '1.3.6.1.2.1.15.3.1.2.10.5.0.93', '1.3.6.1.2.1.15.3.1.2.10.5.0.101',
                '1.3.6.1.2.1.15.3.1.2.10.5.0.109', '1.3.6.1.2.1.15.3.1.2.10.5.0.117', '1.3.6.1.2.1.15.3.1.2.10.6.0.5',
                '1.3.6.1.2.1.15.3.1.2.10.6.0.13', '1.3.6.1.2.1.15.3.1.2.10.6.0.21', '1.3.6.1.2.1.15.3.1.2.10.6.0.29',
                '1.3.6.1.2.1.15.3.1.2.10.6.0.37', '1.3.6.1.2.1.15.3.1.2.10.6.0.45', '1.3.6.1.2.1.15.3.1.2.10.5.100.5',
                '1.3.6.1.2.1.15.3.1.2.10.5.100.13', '1.3.6.1.2.1.15.3.1.2.10.5.100.21',
                '1.3.6.1.2.1.15.3.1.2.107.154.7.243', '1.3.6.1.2.1.15.3.1.2.69.174.0.57',
                '1.3.6.1.2.1.15.3.1.2.192.80.16.145', '1.3.6.1.2.1.15.3.1.2.192.168.15.2',
                '1.3.6.1.2.1.15.3.1.2.192.168.15.6', '1.3.6.1.2.1.15.3.1.2.192.168.15.10',
                '1.3.6.1.2.1.15.3.1.2.192.168.15.14', '1.3.6.1.2.1.15.3.1.2.192.168.15.26',
                '1.3.6.1.2.1.15.3.1.2.192.168.15.30', '1.3.6.1.2.1.15.3.1.2.172.23.1.6',
                '1.3.6.1.2.1.15.3.1.2.172.23.1.2', '1.3.6.1.2.1.15.3.1.2.172.23.0.10',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.14', '1.3.6.1.2.1.15.3.1.2.172.23.0.6',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.26', '1.3.6.1.2.1.15.3.1.2.172.23.0.30',
                '1.3.6.1.2.1.15.3.1.2.172.23.1.10', '1.3.6.1.2.1.15.3.1.2.172.23.0.70',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.74', '1.3.6.1.2.1.15.3.1.2.172.23.0.50',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.82', '1.3.6.1.2.1.15.3.1.2.172.23.0.86',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.90', '1.3.6.1.2.1.15.3.1.2.172.23.0.94',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.98', '1.3.6.1.2.1.15.3.1.2.172.23.0.102',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.106', '1.3.6.1.2.1.15.3.1.2.172.23.0.110',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.114', '1.3.6.1.2.1.15.3.1.2.172.23.0.118',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.122', '1.3.6.1.2.1.15.3.1.2.192.168.15.18',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.142', '1.3.6.1.2.1.15.3.1.2.172.23.0.126',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.130', '1.3.6.1.2.1.15.3.1.2.172.23.0.146',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.150', '1.3.6.1.2.1.15.3.1.2.172.23.0.170',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.174', '1.3.6.1.2.1.15.3.1.2.172.23.0.154',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.158', '1.3.6.1.2.1.15.3.1.2.172.23.0.162',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.166', '1.3.6.1.2.1.15.3.1.2.172.23.0.178',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.190', '1.3.6.1.2.1.15.3.1.2.172.23.0.182',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.186', '1.3.6.1.2.1.15.3.1.2.192.168.240.29',
                '1.3.6.1.2.1.15.3.1.2.192.168.242.29', '1.3.6.1.2.1.15.3.1.2.172.23.0.194',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.198', '1.3.6.1.2.1.15.3.1.2.172.23.0.202',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.206', '1.3.6.1.2.1.15.3.1.2.172.23.0.210',
                '1.3.6.1.2.1.15.3.1.2.10.6.3.5', '1.3.6.1.2.1.15.3.1.2.10.6.3.13', '1.3.6.1.2.1.15.3.1.2.10.7.1.5',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.218', '1.3.6.1.2.1.15.3.1.2.172.23.0.222',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.226', '1.3.6.1.2.1.15.3.1.2.198.32.118.244',
                '1.3.6.1.2.1.15.3.1.2.198.32.118.246', '1.3.6.1.2.1.15.3.1.2.198.32.118.241',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.230', '1.3.6.1.2.1.15.3.1.2.172.23.0.234',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.238', '1.3.6.1.2.1.15.3.1.2.198.32.118.82',
                '1.3.6.1.2.1.15.3.1.2.208.76.14.223', '1.3.6.1.2.1.15.3.1.2.192.168.15.249',
                '1.3.6.1.2.1.15.3.1.2.192.168.15.250', '1.3.6.1.2.1.15.3.1.2.192.168.15.251',
                '1.3.6.1.2.1.15.3.1.2.192.168.15.252', '1.3.6.1.2.1.15.3.1.2.192.168.15.253',
                '1.3.6.1.2.1.15.3.1.2.172.23.1.14', '1.3.6.1.2.1.15.3.1.2.172.23.1.18',
                '1.3.6.1.2.1.15.3.1.2.198.32.118.240', '1.3.6.1.2.1.15.3.1.2.172.23.0.242',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.246', '1.3.6.1.2.1.15.3.1.2.4.14.221.65',
                '1.3.6.1.2.1.15.3.1.2.4.14.216.33', '1.3.6.1.2.1.15.3.1.2.172.23.0.250',
                '1.3.6.1.2.1.15.3.1.2.172.23.0.138', '1.3.6.1.2.1.15.3.1.2.198.32.118.79',
                '1.3.6.1.2.1.15.3.1.2.172.21.0.154', '1.3.6.1.2.1.15.3.1.2.172.21.1.34',
                '1.3.6.1.2.1.15.3.1.2.66.208.229.97', '1.3.6.1.2.1.15.3.1.2.192.168.15.38',
                '1.3.6.1.2.1.15.3.1.2.198.32.118.45', '1.3.6.1.2.1.15.3.1.2.192.145.251.113',
                '1.3.6.1.2.1.15.3.1.2.192.80.16.97', '1.3.6.1.2.1.15.3.1.2.192.168.15.242',
                '1.3.6.1.2.1.15.3.1.16.10.6.1.5', '1.3.6.1.2.1.15.3.1.16.10.6.1.13', '1.3.6.1.2.1.15.3.1.16.10.5.0.5',
                '1.3.6.1.2.1.15.3.1.16.10.5.0.13', '1.3.6.1.2.1.15.3.1.16.10.5.0.21', '1.3.6.1.2.1.15.3.1.16.10.5.0.29',
                '1.3.6.1.2.1.15.3.1.16.10.5.0.37', '1.3.6.1.2.1.15.3.1.16.10.5.0.45', '1.3.6.1.2.1.15.3.1.16.10.5.0.53',
                '1.3.6.1.2.1.15.3.1.16.10.5.0.61', '1.3.6.1.2.1.15.3.1.16.10.5.0.69', '1.3.6.1.2.1.15.3.1.16.10.5.0.77',
                '1.3.6.1.2.1.15.3.1.16.10.5.0.85', '1.3.6.1.2.1.15.3.1.16.10.5.0.93',
                '1.3.6.1.2.1.15.3.1.16.10.5.0.101', '1.3.6.1.2.1.15.3.1.16.10.5.0.109',
                '1.3.6.1.2.1.15.3.1.16.10.5.0.117', '1.3.6.1.2.1.15.3.1.16.10.6.0.5', '1.3.6.1.2.1.15.3.1.16.10.6.0.13',
                '1.3.6.1.2.1.15.3.1.16.10.6.0.21', '1.3.6.1.2.1.15.3.1.16.10.6.0.29', '1.3.6.1.2.1.15.3.1.16.10.6.0.37',
                '1.3.6.1.2.1.15.3.1.16.10.6.0.45', '1.3.6.1.2.1.15.3.1.16.10.5.100.5',
                '1.3.6.1.2.1.15.3.1.16.10.5.100.13', '1.3.6.1.2.1.15.3.1.16.10.5.100.21',
                '1.3.6.1.2.1.15.3.1.16.107.154.7.243', '1.3.6.1.2.1.15.3.1.16.69.174.0.57',
                '1.3.6.1.2.1.15.3.1.16.192.80.16.145', '1.3.6.1.2.1.15.3.1.16.192.168.15.2',
                '1.3.6.1.2.1.15.3.1.16.192.168.15.6', '1.3.6.1.2.1.15.3.1.16.192.168.15.10',
                '1.3.6.1.2.1.15.3.1.16.192.168.15.14', '1.3.6.1.2.1.15.3.1.16.192.168.15.26',
                '1.3.6.1.2.1.15.3.1.16.192.168.15.30', '1.3.6.1.2.1.15.3.1.16.172.23.1.6',
                '1.3.6.1.2.1.15.3.1.16.172.23.1.2', '1.3.6.1.2.1.15.3.1.16.172.23.0.10',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.14', '1.3.6.1.2.1.15.3.1.16.172.23.0.6',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.26', '1.3.6.1.2.1.15.3.1.16.172.23.0.30',
                '1.3.6.1.2.1.15.3.1.16.172.23.1.10', '1.3.6.1.2.1.15.3.1.16.172.23.0.70',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.74', '1.3.6.1.2.1.15.3.1.16.172.23.0.50',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.82', '1.3.6.1.2.1.15.3.1.16.172.23.0.86',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.90', '1.3.6.1.2.1.15.3.1.16.172.23.0.94',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.98', '1.3.6.1.2.1.15.3.1.16.172.23.0.102',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.106', '1.3.6.1.2.1.15.3.1.16.172.23.0.110',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.114', '1.3.6.1.2.1.15.3.1.16.172.23.0.118',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.122', '1.3.6.1.2.1.15.3.1.16.192.168.15.18',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.142', '1.3.6.1.2.1.15.3.1.16.172.23.0.126',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.130', '1.3.6.1.2.1.15.3.1.16.172.23.0.146',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.150', '1.3.6.1.2.1.15.3.1.16.172.23.0.170',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.174', '1.3.6.1.2.1.15.3.1.16.172.23.0.154',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.158', '1.3.6.1.2.1.15.3.1.16.172.23.0.162',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.166', '1.3.6.1.2.1.15.3.1.16.172.23.0.178',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.190', '1.3.6.1.2.1.15.3.1.16.172.23.0.182',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.186', '1.3.6.1.2.1.15.3.1.16.192.168.240.29',
                '1.3.6.1.2.1.15.3.1.16.192.168.242.29', '1.3.6.1.2.1.15.3.1.16.172.23.0.194',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.198', '1.3.6.1.2.1.15.3.1.16.172.23.0.202',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.206', '1.3.6.1.2.1.15.3.1.16.172.23.0.210',
                '1.3.6.1.2.1.15.3.1.16.10.6.3.5', '1.3.6.1.2.1.15.3.1.16.10.6.3.13', '1.3.6.1.2.1.15.3.1.16.10.7.1.5',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.218', '1.3.6.1.2.1.15.3.1.16.172.23.0.222',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.226', '1.3.6.1.2.1.15.3.1.16.198.32.118.244',
                '1.3.6.1.2.1.15.3.1.16.198.32.118.246', '1.3.6.1.2.1.15.3.1.16.198.32.118.241',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.230', '1.3.6.1.2.1.15.3.1.16.172.23.0.234',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.238', '1.3.6.1.2.1.15.3.1.16.198.32.118.82',
                '1.3.6.1.2.1.15.3.1.16.208.76.14.223', '1.3.6.1.2.1.15.3.1.16.192.168.15.249',
                '1.3.6.1.2.1.15.3.1.16.192.168.15.250', '1.3.6.1.2.1.15.3.1.16.192.168.15.251',
                '1.3.6.1.2.1.15.3.1.16.192.168.15.252', '1.3.6.1.2.1.15.3.1.16.192.168.15.253',
                '1.3.6.1.2.1.15.3.1.16.172.23.1.14', '1.3.6.1.2.1.15.3.1.16.172.23.1.18',
                '1.3.6.1.2.1.15.3.1.16.198.32.118.240', '1.3.6.1.2.1.15.3.1.16.172.23.0.242',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.246', '1.3.6.1.2.1.15.3.1.16.4.14.221.65',
                '1.3.6.1.2.1.15.3.1.16.4.14.216.33', '1.3.6.1.2.1.15.3.1.16.172.23.0.250',
                '1.3.6.1.2.1.15.3.1.16.172.23.0.138', '1.3.6.1.2.1.15.3.1.16.198.32.118.79',
                '1.3.6.1.2.1.15.3.1.16.172.21.0.154', '1.3.6.1.2.1.15.3.1.16.172.21.1.34',
                '1.3.6.1.2.1.15.3.1.16.66.208.229.97', '1.3.6.1.2.1.15.3.1.16.192.168.15.38',
                '1.3.6.1.2.1.15.3.1.16.198.32.118.45', '1.3.6.1.2.1.15.3.1.16.192.145.251.113',
                '1.3.6.1.2.1.15.3.1.16.192.80.16.97', '1.3.6.1.2.1.15.3.1.16.192.168.15.242']
    # pdb.set_trace()
    date_start = datetime.datetime.now()
    lst_ret = self.execute(str_address, lst_oids)
    date_end = datetime.datetime.now()
    print(date_end - date_start)
    pdb.set_trace()
    return
    for str_oid in lst_oids:
        _thread.start_new_thread(test_sub, (self, str_address, [str_oid]))
    pdb.set_trace()
    return
    ret = self.execute('10.200.100.2', ['1.3.6.1.2.1.15.3.1.1.10.200.95.238', '1.3.6.1.2.1.15.3.1.1.10.5.0.5',
                                        '1.3.6.1.2.1.15.3.1.1.10.5.0.6'])
    pdb.set_trace()
    self.disconnect()

    for i in range(2):
        print("start:" + str(i) + " " + str(datetime.datetime.now()))
        _thread.start_new_thread(test_sub, (self, i))
        print("end:" + str(i) + " " + str(datetime.datetime.now()))
    pdb.set_trace()
    self.disconnect()

    self.execute_old("")
    # self.execute('10.200.100.2',['1.3.6.1.2.1.15.3.1.1.10.200.95.238'])
    tmp = dir()
    pdb.set_trace()


test()
