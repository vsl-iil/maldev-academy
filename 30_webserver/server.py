# Adapted from:
# https://gist.github.com/sjb9774/eeabe6401b3c467d9489339e88dae9f0

import time
import datetime
import re
import socket
import select

def file2bytes(path):
    with open(path, 'rb') as f:
        contents = f.read()

    return contents

def respond(url):
    url_response_map = {
            # regex:       response
            r"/success.*":  file2bytes("a.exe"),
            r"/info.*":     b"0123456789a",
            r"/update.*":   b"1",
    }

    for reg, resp in url_response_map.items():
        if re.search(reg, url):
            return resp

    return None


if __name__ == "__main__":
    # Get socket file descriptor as a TCP socket using the IPv4 address family
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set some modes on the socket, not required but it's nice for our uses
    listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    address_port = ("0.0.0.0", 80)
    # reserve address and port
    listener_socket.bind(address_port)
    # listen for connections, a maximum of 1
    listener_socket.listen(1)
    print("Server listening @ 0.0.0.0:80")

    # loop indefinitely to continuously check for new connections
    while True:
        # Poll the socket to see if there are any newly written data, note excess data dumped to "_" variables
        read_ready_sockets, _, _ = select.select(
            [listener_socket],  # list of items we want to check for read-readiness (just our socket)
            [],  # list of items we want to check for write-readiness (not interested)
            [],  # list of items we want to check for "exceptional" conditions (also not interested)
            0.2  # prevent high CPU usage
        )
        # if a value was returned here then we have a connection to read from
        if read_ready_sockets:
            # select.select() returns a list of readable objects, so we'll iterate, but we only expect a single item
            for ready_socket in read_ready_sockets:
                # accept the connection from the client and get its socket object and address
                client_socket, client_address = ready_socket.accept()

                # read up to 4096 bytes of data from the client socket
                client_msg = client_socket.recv(4096)
                print(f"[{datetime.datetime.now().time()}] Client said: {client_msg.decode('utf-8')}")

                # Send a response to the client, notice it is a byte string
                
                if resp := respond(client_msg.decode('utf-8')):
                    client_socket.sendall(resp)
                else:
                    client_socket.sendall(
                        bytes(f"""HTTP/1.1 200 OK\r\nContent-type: text/html\r\nSet-Cookie: ServerName=steveserver\r
                        \r\n
                        <!doctype html>
                        <html>
                            <head/>
                            <body>
                                <h1>Welcome to the server!</h1>
                                <h2>Server address: {address_port[0]}:{address_port[1]}</h2>
                                <h3>You're connected through address: {client_address[0]}:{client_address[1]}</h3>
                                <body>
                                    <pre>{client_msg.decode("utf-8")}<pre>
                                </body>
                            </body>
                        </html>
                        \r\n\r\n
                        """, "utf-8")
                    )
                try:
                    # close the connection
                    client_socket.close()
                except OSError:
                    # client disconnected first, nothing to do
                    pass