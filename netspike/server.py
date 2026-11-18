"""A tiny line based TCP echo server.

Protocol: client sends one line ending in a newline, server replies
with "ok " plus the same line. One request per connection, which
keeps the load client honest: every measurement includes connect,
send, and receive, exactly the path a latency spike would hurt.

The server can run in a thread (tests) or as its own process
(experiments, where a separate pid is the whole point: schedstat,
status, and process state are per process kernel data).
"""

import hashlib
import socket
import sys
import threading


class EchoServer:
    def __init__(self, host="127.0.0.1", port=0, work_iterations=0):
        self.host = host
        # When work_iterations > 0, every request first burns a
        # fixed amount of CPU (pbkdf2 iterations). A CPU limit or a
        # saturated machine then has something to bite on; with the
        # default 0 the reply is as cheap as an echo can be.
        self.work_iterations = work_iterations
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(128)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = None
        self.served = 0

    def _handle(self, conn):
        try:
            conn.settimeout(5.0)
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if data:
                if self.work_iterations:
                    hashlib.pbkdf2_hmac("sha256", data, b"netspike-work",
                                        self.work_iterations)
                conn.sendall(b"ok " + data)
                self.served += 1
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def serve_forever(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def start_in_thread(self):
        self._thread = threading.Thread(target=self.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Usage: python -m netspike.server [PORT] [--work]
    # --work makes every request burn a fixed amount of CPU first
    # (see EchoServer.work_iterations). This is the server-only
    # entrypoint the Docker experiment uses inside its containers.
    work = "--work" in argv
    numbers = [a for a in argv if a.isdigit()]
    port = int(numbers[0]) if numbers else 0
    server = EchoServer(port=port,
                        work_iterations=20000 if work else 0)
    # The parent process reads this line to learn the bound port and
    # confirm the server is up before sending any load.
    print("READY %d" % server.port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
