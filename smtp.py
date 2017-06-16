#!/usr/bin/env python3
"""SMTP-client realization."""
import sys
import re

from socket import socket, AF_INET, SOCK_STREAM, timeout
from ssl import wrap_socket
from argparse import ArgumentParser
from os import getcwd, path, listdir, linesep
from logging import error
from base64 import b64encode
from getpass import getpass


# Actualy, this group of parameters
# should be set as the program arguments
# for the ability of other mail servers using.
SERVER = "mxs.mail.ru"
SSL_SERVER = "smtp.mail.ru"
PORT = 25
SSL_PORT = 587

TIMEOUT = 3
ALLOWED_EXTENSIONS = ["jpg", "png", "gif", "bmp", "jpeg"]
SERVER_REPLY_BUFFER = 50

EMAIL_PATTERN = re.compile(r".*?@.*?\..*?")
CRLF = "\r\n"
ENCODING = "windows-1251"


def main():
    """Pictures searching, a letter assembling and sending."""
    sender, destination, directory, ssl = argument_parse()

    if re.search(EMAIL_PATTERN, sender) is None:
        error("Incorrect sender.")
        sys.exit(0)

    if re.search(EMAIL_PATTERN, destination) is None:
        error("Incorrect recipient.")
        sys.exit(0)

    if not path.exists(directory) or not path.isdir(directory):
        error("Incorrect directory.")
        sys.exit(0)

    pictures = [path.basename(picture) for picture in get_pictures(directory)]
    names = ""
    for picture in pictures:
        names += picture + ", "
    names = names[:-2]

    print("Found pictures: {}".format(names))
    print("Are you sure to send this pictures to {}?[y/n]".format(destination))

    while True:
        confirmation = input()
        if confirmation in "yY" or confirmation == "":
            letter = get_letter(pictures, directory, sender, destination)
            if ssl:
                handle_ssl_connection(sender, destination, letter)
            else:
                handle_connection(sender, destination, letter)
            break
        elif confirmation in "nN":
            break


def argument_parse():
    """Arguments parsing."""
    parser = ArgumentParser(prog="python3 smtp.py", \
        description="A tool for a given directory all of pictures to recipient sending.", \
        epilog="(c) Semyon Makhaev, 2016. All rights reserved.")
    parser.add_argument("sender", type=str, help="A sender email.")
    parser.add_argument("recipient", type=str, help="A destination email.")
    parser.add_argument("directory", type=str, nargs='?', default=getcwd(), \
        help="A directory of pictures for sending.")
    parser.add_argument("-s", "--ssl", action="store_true", help="A sequrity connection.")
    args = parser.parse_args()
    return args.sender, args.recipient, args.directory, args.ssl


def get_pictures(directory):
    """Returns a list of pictures paths."""
    for filename in listdir(directory):
        point_idx = filename.find('.')
        if point_idx > 0 and filename[point_idx+1:] in ALLOWED_EXTENSIONS:
            yield filename


def get_letter(pictures, directory, sender, destination):
    """A letter assembling."""
    header_from = "From: <{}>{}".format(sender, CRLF)
    header_to = "To: <{}>{}".format(destination, CRLF)
    subject = "Subject: Pictures{}".format(CRLF)

    # A generated randomize symbols sequence should be used as boundary.
    # Actualy, those symbols shouldnt occur in a letter (by RFC).
    boundary = "qwer"

    dash_dash_boundary = "--{}".format(boundary)
    header_content = "Content-Type: multipart/related; charset={}; ".format(ENCODING)
    header_boundary = "boundary={}{}".format(boundary, CRLF)
    header = header_from + header_to + subject + header_content + header_boundary

    body = dash_dash_boundary + CRLF
    body += "Content-Type: text/html; charset={}{}".format(ENCODING, CRLF * 2)
    for picture in pictures:
        body += '<img src="cid:{}">{}'.format(picture, CRLF * 2)
    body += dash_dash_boundary + CRLF

    for picture in pictures:
        extension = picture[picture.find('.')+1:]
        body += "Content-Type: image/{}{}".format(extension, CRLF)
        body += "Content-Transfer-Encoding: base64{}".format(CRLF)
        body += "Content-ID: <{}>{}".format(picture, CRLF)
        body += 'Content-Disposition: attachment; filename="{}"{}'.format(picture, CRLF * 2)
        body += read_picture(directory, picture) + (CRLF * 2)
    body += dash_dash_boundary + "--" + (CRLF * 2) + "."

    return header + CRLF + body


def read_picture(directory, picture):
    """Reads a picture and returns it in base-64 encoding."""
    if not directory.endswith(path.sep):
        directory += path.sep

    with open(directory + picture, mode='rb') as letter_file:
        letter = letter_file.read()
        return b64encode(letter).decode(ENCODING)


def handle_connection(source, destination, letter):
    """A simply letter sending."""
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    try:
        sock.connect((SERVER, PORT))
        data = sock.recv(512)
        analyse_data(data, "220 ")

        send_data(sock, "ehlo test", "250")
        send_letter(sock, source, destination, letter)

        print("Yep!")

    except timeout:
        error("Connection time limit exceeded.")

    finally:
        sock.close()


def handle_ssl_connection(source, destination, letter):
    """A letter sending using SSL."""
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    try:
        sock.connect((SSL_SERVER, SSL_PORT))
        data = sock.recv(512)
        analyse_data(data, "220 ")

        send_data(sock, "ehlo test", "250")
        send_data(sock, "starttls", "220")

        ssl_sock = wrap_socket(sock)
        ssl_sock.settimeout(TIMEOUT)

        try:
            send_data(ssl_sock, "ehlo test", "250")
            send_data(ssl_sock, "auth login", "334")

            login = input("Login: ")
            send_data(ssl_sock, b64encode(login.encode(ENCODING)).decode(ENCODING), "334")

            password = getpass("Password: ")
            send_data(ssl_sock, b64encode(password.encode(ENCODING)).decode(ENCODING), "235")

            send_letter(ssl_sock, source, destination, letter)
            print("Yep!")

        finally:
            ssl_sock.close()

    except timeout:
        error("Connection time limit exceeded.")

    finally:
        sock.close()


def send_data(sock, data, response, profile=True):
    """Sends a given data to socket and checks a response."""
    if profile:
        sys.stderr.write(data + linesep)
    sock.send((data + CRLF).encode(ENCODING))
    buff = sock.recv(512)
    analyse_data(buff, response)


def analyse_data(data, correct):
    """Checks that the server sent expected data."""
    sys.stderr.write(data.decode(ENCODING))
    data = data.decode(ENCODING)
    if not data.startswith(correct):
        if len(data) > SERVER_REPLY_BUFFER:
            data = data[:SERVER_REPLY_BUFFER] + "..."
        error("Unexpected server response:{}%s".format(linesep), data)
        sys.exit(0)


def send_letter(sock, source, destination, letter):
    """Sends a few requests to server."""
    send_data(sock, "mail from: {}".format(source), "250")
    send_data(sock, "rcpt to: {}".format(destination), "250")
    send_data(sock, "data", "354")
    send_data(sock, letter, "250", profile=False)
    send_data(sock, "quit", "221")


if __name__ == "__main__":
    main()
