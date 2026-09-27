import asyncio
import json
import ssl
from concurrent.futures import Future
from itertools import count
from threading import Thread

import pytest
import trustme
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic import tls
from aioquic.h3 import events
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded



@pytest.fixture(scope="module")
def browser_echo(tmp_path_factory):
    directory = tmp_path_factory.mktemp("browser-capabilities")
    authority = trustme.CA()
    certificate = authority.issue_cert("127.0.0.1")
    authority.cert_pem.write_to_path(directory / "ca.pem")
    certificate.cert_chain_pems[0].write_to_path(directory / "cert.pem")
    certificate.private_key_pem.write_to_path(directory / "key.pem")
    connections = count(1)
    ready = Future()


    def answer(protocol, connection, headers, body):
        payload = json.dumps({"protocol": protocol, "connection": connection, "headers": [(key.decode(), value.decode()) for key, value in headers], "body": body.decode()}).encode()  # noqa: E501
        return [(b":status", b"200"), (b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())], payload  # noqa: E501


    async def handle_h2(reader, writer):
        connection = next(connections)
        h2 = H2Connection(config=H2Configuration(client_side=False, normalize_inbound_headers=False))  # noqa: E501
        h2.initiate_connection()
        writer.write(h2.data_to_send())
        streams = {}
        try:
            while data := await reader.read(65536):
                for event in h2.receive_data(data):
                    if isinstance(event, RequestReceived):
                        streams[event.stream_id] = [event.headers, bytearray()]
                    elif isinstance(event, DataReceived):
                        streams[event.stream_id][1].extend(event.data)
                        h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)  # noqa: E501
                    elif isinstance(event, StreamEnded):
                        headers, body = streams.pop(event.stream_id)
                        headers, payload = answer("h2", connection, headers, body)
                        h2.send_headers(event.stream_id, headers)
                        h2.send_data(event.stream_id, payload, end_stream=True)
                writer.write(h2.data_to_send())
                await writer.drain()
        finally:
            writer.close()


    class H3Server(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = H3Connection(self._quic)
            self.connection = next(connections)
            self.streams = {}


        def quic_event_received(self, event):
            for item in self.http.handle_event(event):
                if isinstance(item, events.HeadersReceived):
                    self.streams[item.stream_id] = [item.headers, bytearray()]
                elif isinstance(item, events.DataReceived):
                    self.streams[item.stream_id][1].extend(item.data)
                if isinstance(item, (events.HeadersReceived, events.DataReceived)) and item.stream_ended:  # noqa: E501
                    headers, body = self.streams.pop(item.stream_id)
                    headers, payload = answer("h3", self.connection, headers, body)
                    parameters = next(value.hex() for extension, value in self._quic.tls.received_extensions if extension == tls.ExtensionType.QUIC_TRANSPORT_PARAMETERS)  # noqa: E501
                    payload = json.dumps(json.loads(payload) | {"quic_version": self._quic._version, "quic_transport_parameters": parameters}).encode()  # noqa: E501
                    headers[-1] = (b"content-length", str(len(payload)).encode())
                    self.http.send_headers(item.stream_id, headers)
                    self.http.send_data(item.stream_id, payload, end_stream=True)
            self.transmit()


    async def run():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certificate.configure_cert(context)
        context.set_alpn_protocols(["h2"])
        config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        config.load_cert_chain(str(directory / "cert.pem"), str(directory / "key.pem"))  # noqa: E501
        tcp = await asyncio.start_server(handle_h2, "127.0.0.1", 0, ssl=context)
        port = tcp.sockets[0].getsockname()[1]
        quic = await serve("127.0.0.1", port, configuration=config, create_protocol=H3Server)  # noqa: E501
        stop = asyncio.get_running_loop().create_future()
        ready.set_result((port, asyncio.get_running_loop(), stop))
        async with tcp:
            await stop
        quic.close()

    thread = Thread(target=lambda: asyncio.run(run()), daemon=True)
    thread.start()
    port, loop, stop = ready.result(timeout=10)
    try:
        yield f"https://127.0.0.1:{port}", str(directory / "ca.pem")
    finally:
        loop.call_soon_threadsafe(stop.set_result, None)
        thread.join(timeout=10)
        assert not thread.is_alive()
