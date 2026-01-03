#cli.py
import argparse
from chatroom.client import start_client
from chatroom.server import server_main


def main():
    parser = argparse.ArgumentParser(
        prog="chatroom",
        description="Simple encrypted TCP chatroom client/server."
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Client IP or hostname (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5555,
        help="Server port (default: 5555)",
    )

    parser.add_argument(
        "--server",
        action="store_true",
        help="Run in server mode (default: client)",
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="Server IP (default 0.0.0.0)",
    )

    args = parser.parse_args()

    if args.server:
        server_main(args.bind, args.port)
    else:
        start_client(args.host, args.port)

