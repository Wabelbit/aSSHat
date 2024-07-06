#!/usr/bin/env python3
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Tuple, Optional

import paramiko
import typer
from tinydb import TinyDB, Query
from tinydb.queries import QueryLike

SSHD_BANNER = "SSH-2.0-OpenSSH_8.7"
MAX_TRIES = 5

NetAddr = Tuple[str, int]

host_key: paramiko.RSAKey
running = True
dbg_lock = threading.Lock()


class Jobs:
    def __init__(self):
        self._jobs = []  # things for workers to work on
        self.sem = threading.Semaphore(0)  # tracks the number of items available in jobs
        self._lock = threading.Lock()  # lock to mutate the list

    def add(self, sock: socket.socket, addr: NetAddr):
        with self._lock:
            self._jobs.append((sock, addr))
        self.sem.release(1)

    def take(self) -> Tuple[Optional[socket.socket], Optional[NetAddr]]:
        self.sem.acquire()  # wait to be released by the main thread
        with self._lock:
            if self._jobs:
                return self._jobs.pop(0)
            return None, None


class Database:
    def __init__(self, path: Path):
        self._db = TinyDB(path)
        self._db_lock = threading.Lock()

    def write(self, ip: str, username: str, password: str):
        db_row = Query()
        pk_query: QueryLike = (db_row.ip == ip) & (db_row.username == username) & (db_row.password == password)
        with self._db_lock:
            row = self._db.search(pk_query)
            now = datetime.now().astimezone().isoformat()
            if row:
                # update existing entry
                new_count = row[0]["count"] + 1
                out(f"[{now} update] ip={ip}, user={username}, pass={password} -> {new_count}")
                self._db.update({"updated": now, "count": new_count}, pk_query)
            else:
                out(f"[{now}    new] ip={ip}, user={username}, pass={password}")
                self._db.insert({"ip": ip,
                                 "username": username,
                                 "password": password,
                                 "count": 1,
                                 "created": now,
                                 "updated": now,
                                 })


def dbg(*args, **kwargs):
    if "worker" in kwargs:
        args = [f"[worker {kwargs['worker']}]", *args]
        del kwargs['worker']
    with dbg_lock:
        print(*args, **kwargs, file=sys.stderr)


def out(*args, **kwargs):
    with dbg_lock:
        print(*args, **kwargs, file=sys.stdout)


class SshServer(paramiko.ServerInterface):
    def __init__(self, db: Database, ip):
        self.event = threading.Event()
        self._attempts_left = MAX_TRIES
        self._db = db
        self._ip = ip

    def check_auth_password(self, username, password):
        self._db.write(self._ip, username, password)
        self._attempts_left -= 1
        if self._attempts_left <= 0:
            self.event.set()
        return paramiko.common.AUTH_FAILED  # return failed to convince them to try again so that we can farm more data

    def get_allowed_auths(self, username):
        return "password"

    def get_banner(self):
        return (SSHD_BANNER, "en-US") or super().get_banner()


def worker(worker_id: int, jobs: Jobs, db: Database):
    dbg("alive", worker=worker_id)
    try:
        while True:
            sock, addr = jobs.take()
            if not running:
                break
            ip, port = addr

            transport = paramiko.Transport(sock)
            transport.local_version = SSHD_BANNER
            transport.add_server_key(host_key)
            server = SshServer(db, ip)
            try:
                transport.start_server(server=server)
                server.event.wait(5)
            except Exception as e:
                dbg("error", ip, e, worker=worker_id)
            finally:
                time.sleep(0.25)
                transport.close()
                dbg("bye", ip, worker=worker_id)
    finally:
        dbg("quit", worker=worker_id)


def main(port: int = 2222, workers: int = 8, output: Path = "asshats.json"):
    global running
    global host_key

    dbg("Generating host key")
    host_key = paramiko.RSAKey.generate(2048)

    db = Database(output)
    jobs = Jobs()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('', port))
    server.listen(workers * 4)

    worker_threads = [threading.Thread(name=f"worker {i}", target=worker, args=[i, jobs, db]) for i in range(workers)]
    for thread in worker_threads:
        thread.start()

    while True:
        try:
            sock, addr = server.accept()
            dbg("accept", addr, worker="main")
            jobs.add(sock, addr)
            continue
        except KeyboardInterrupt:
            dbg("QUITTING!")
        except Exception as e:
            print(e)

        # shut down
        dbg("main waiting for workers")
        running = False
        jobs.sem.release(workers)
        for thread in worker_threads:
            thread.join()
        break


if __name__ == '__main__':
    typer.run(main)
