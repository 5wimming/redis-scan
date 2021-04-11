#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Date    : 2021/04/11
# @Author  : weinull,5wimming

import os
import time
import queue
import logging
import requests
import threading
import sys
# 引入需调用的脚本
import task


# log配置
log_format = '[%(asctime)s]-[%(levelname)s] - %(message)s'
time_format = '%Y-%m-%d %H:%M:%S'
logging.basicConfig(
    level=logging.INFO,
    format=log_format,
    datefmt=time_format,
    filename=time.strftime('task.log'),
    filemode='a'
)
# 配置log输出到console
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter(log_format, time_format))
logging.getLogger('').addHandler(console)

# 线程锁
thread_mutex = threading.Lock()
# 线程数
thread_max = 50
# 数据文件
input_file = 'input_data.txt'
account = ''
password = ''
weakly_passwords = ['redis', 'redis123', 'Redis123', 'redis@123', 'root', 'oracle', 'password', 'p@ssw0rd', 'abc123!', '123456', 'admin', 'abc123', 'admin12', 'admin888', 'admin8', 'admin123', 'sysadmin', 'adminxxx', 'adminx', '6kadmin', 'base', 'feitium', 'admins', 'roots', 'test', 'test1', 'test123', 'test2', 'aaaAAA111', '888888', '88888888', '000000', '00000000', '111111', '11111111', 'aaaaaa', 'aaaaaaaa', '135246', '135246789', '654321', '12345', '54321', '123456789', '1234567890', '123qwe', '123qweasd', 'qweasd', '123asd', 'qwezxc', 'qazxsw', 'qazwsx', 'qazwsxedc', '1qaz2wsx', 'zxcvbn', 'asdfgh', 'qwerty', 'qazxdr', 'qwaszx', '123123', '123321', 'abcdef', 'abcdefg', '88888', '55555', 'aaaaa', 'asd123', 'qweasdzxc', 'zxcvb', 'asdfg', 'qwert', 'qwe', 'qwer', 'welcome', 'ABC_abc1', 'Admin@1234']
current_password = ''
password_scan_flag = 'init'  # 扫描方式开关
auto_refresh_cookie = 5000000


def get_cookie():
    global cookie
    cookie = 'tmp_cookie'
    return cookie


def start_hello():
    print('''readis scan 
                            by 5wimming''')


def thread_process_func(task_queue, result_queue):
    global cookie
    while True:
        try:
            try:
                target = task_queue.get_nowait()
            except queue.Empty:
                logging.info('{} Task done'.format(threading.current_thread().name))
                result_queue.put_nowait('Task done')
                break
            logging.info('[{}] - {}'.format(task_queue.qsize(), target))
            # 调用任务处理函数并取处理结果到result_queue
            result = str(task.main(target, current_password, password_scan_flag)).strip()
            result_queue.put_nowait(result)
        except Exception as e:
            logging.error('{} - {}'.format(threading.current_thread().name, e))


def thread_result_func(result_queue, output_file):
    thread_done_total = 0
    result_total = 0
    try:
        with open(output_file, 'w', encoding='UTF-8') as fw:
            while True:
                try:
                    result = result_queue.get()
                    result_total += 1
                    if not result_total % auto_refresh_cookie:
                        get_cookie()
                    if result == 'Task done':
                        thread_done_total += 1
                        if thread_done_total == thread_max:
                            break
                        else:
                            continue
                    fw.write('{}\n'.format(result))
                    fw.flush()
                except Exception as e:
                    logging.error('{} - {}'.format(threading.current_thread().name, e))
    except Exception as e:
        logging.error('{} - {}'.format(threading.current_thread().name, e))


def main():
    logging.info('-' * 50)
    if not os.path.exists(input_file):
        logging.error('Not found input file: {}'.format(input_file))
        logging.info('-' * 50)
        exit(0)

    logging.info('Read data')
    with open(input_file, encoding='UTF-8') as fr:
        input_data = fr.readlines()

    logging.info('Create queue')
    task_queue = queue.Queue()
    for data in input_data:
        task_queue.put_nowait(data.strip())

    result_queue = queue.Queue()
    thread_list = list()

    # 获取登录Cookie
    get_cookie()

    # 任务处理线程
    logging.info('Create thread')
    for x in range(thread_max):
        thread = threading.Thread(target=thread_process_func, args=(task_queue, result_queue))
        thread.start()
        thread_list.append(thread)
    # 结果输出线程
    output_file = time.strftime('result_data_%Y%m%d%H%M%S.txt')
    result_thread = threading.Thread(target=thread_result_func, args=(result_queue, output_file), name='Result Thread')
    result_thread.start()
    for thread in thread_list:
        thread.join()
    result_thread.join()

    logging.info('All Task Done')
    logging.info('Output result: {}'.format(output_file))
    logging.info('-' * 50)


if __name__ == '__main__':
    args = sys.argv
    start_hello()
    for key in args:
        if key in ['-w', '--weak_password']:
            password_scan_flag = True
            for i, password in enumerate(weakly_passwords):
                current_password = password
                main()
                time.sleep(5)
        elif key in ['-u', '--unauthorized_access']:
            password_scan_flag = False
            main()
    if password_scan_flag == 'init':
        print('1、未授权访问扫描：python3 thread_task.py -u \n 2、弱口令扫描：python3 thread_task.py -w ')
    exit(0)
