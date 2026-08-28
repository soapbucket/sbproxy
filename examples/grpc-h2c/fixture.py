#!/usr/bin/env python3
"""Local gRPC echo upstream for the grpc-h2c example.

Implements `sbproxy_e2e.echo.Echo/Hello` on plaintext HTTP/2 so the
proxy can demonstrate h2c passthrough, gRPC-Web, and REST transcode
without an operator-supplied server.

Requires the `grpcio` and `grpcio-tools` packages:

    python3 -m pip install grpcio grpcio-tools
    python3 fixture.py [port]

Defaults to port 50051, matching the example's sb.yml.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROTO = HERE / "echo.proto"


def _die(message: str, code: int = 1) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def _load_stubs():
    try:
        from grpc_tools import protoc
    except ImportError:
        _die(
            "grpc-h2c fixture needs grpcio-tools. Install with:\n"
            "  python3 -m pip install grpcio grpcio-tools"
        )
    work = Path(tempfile.mkdtemp(prefix="grpc-h2c-"))
    rc = protoc.main(
        [
            "protoc",
            f"-I{HERE}",
            f"--python_out={work}",
            f"--grpc_python_out={work}",
            str(PROTO),
        ]
    )
    if rc != 0:
        _die(f"failed to compile {PROTO.name} (protoc exit {rc})")
    sys.path.insert(0, str(work))
    import echo_pb2
    import echo_pb2_grpc

    return echo_pb2, echo_pb2_grpc


def main() -> None:
    try:
        import grpc
        from concurrent import futures
    except ImportError:
        _die(
            "grpc-h2c fixture needs grpcio. Install with:\n"
            "  python3 -m pip install grpcio grpcio-tools"
        )

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 50051
    echo_pb2, echo_pb2_grpc = _load_stubs()

    class Echo(echo_pb2_grpc.EchoServicer):
        def Hello(self, request, context):
            return echo_pb2.EchoResponse(message=request.message)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    echo_pb2_grpc.add_EchoServicer_to_server(Echo(), server)
    bound = server.add_insecure_port(f"127.0.0.1:{port}")
    if bound == 0:
        _die(f"could not bind 127.0.0.1:{port}")
    server.start()
    print(f"grpc-h2c fixture listening on 127.0.0.1:{port}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
