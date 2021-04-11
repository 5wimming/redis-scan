#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Date    : 2021/04/11
# @Author  : 5wimming

import urllib3
import socket
urllib3.disable_warnings()


def unauthorized_access_scan(target, password):
    scan_result = ''
    ip, port = target.split(':')
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send("INFO\r\n".encode())
        result = s.recv(1024).decode()
        print(ip, port, result)

        if "redis_version" in result:
            scan_result = "{0}--未授权访问".format(target)
    except Exception as e:
        print('unauthorized access scan:', e)
    s.close()
    return scan_result


def weak_password_scan(target, password):
    ip, port = target.split(':')
    scan_result = ''
    try:
        passwd = password.strip("\n")
        socket.setdefaulttimeout(2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send(("AUTH %s\r\n" % passwd).encode())
        result = s.recv(1024).decode()
        print(ip, port, result)

        if 'OK' in result:
            scan_result = "{0}--弱口令：{1}".format(target, passwd)
        else:
            scan_result = "{0}--强密码".format(target)
    except Exception as e:
        print('weak password scan:', e)
    s.close()
    return scan_result


def main(target, password, password_scan_flag):
    target = target.strip()
    if password_scan_flag:
        return weak_password_scan(target, password)
    else:
        return unauthorized_access_scan(target, password)


if __name__ == '__main__':
    print(main('100.80.10.10:6379', 'admin', password_scan_flag=False))
