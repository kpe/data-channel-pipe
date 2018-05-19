import asyncio

import logbook
import logbook.more
import websockets

#
# Based on the signaling server implementation by Lennart Grahl 
# from https://github.com/rawrtc/rawrtc-terminal-demo 
#
# This version is slightly modified to assign a role, i.e.
# a 0 or 1 to the connected peers. Also the expected
# ws_uri does not contain a slot, i.e. both peers would use
# the same uri, e.g. ws://127.0.0.1:9765/test
#

PING_INTERVAL = 5.0
PING_TIMEOUT = 10.0

class SignalingError(Exception):
    pass

class MessageFlowError(SignalingError):
    pass

class PathClient:
    def __init__(self, path, slot, connection):
        self.path = path
        self.connection = connection
        self.slot = slot
        self.peer = None
        self.log = logbook.Logger(self.name)
        if self.connection.open:
            self.log.debug('Open')
        
        self.path.clients[self.slot] = self
                
            
    def __repr__(self):
        return '<{} at {}>'.format(self.name, hex(id(self)))
    
    @property
    def name(self):
        return '{}.{}'.format(self.path.name, self.slot)
    
    @property
    def open(self):
        return self.connection.open
    
    def close(self, code=1000, reason=''):
        if self.connection.open:
            self.log.debug('Closing')
            self.loop.create_task(self.connection.close(code=code, reason=reason))
        self.path.clients[self.slot] = None
        if self.peer is not None:
            self.peer.peer = None
            self.peer = None

    def receive(self):
        return self.connection.recv()

    def send(self, message):
        return self.connection.send(message)

    def ping(self):
        return self.connection.ping()
    
class Path:
    def __init__(self, loop, path):
        self.name = 'path.{}'.format(path)
        self.loop = loop
        self.log = logbook.Logger(self.name)
        self.slots = {
            0: asyncio.Future(),
            1: asyncio.Future()
        }
        self.clients = {
            0: None,
            1: None
        }

    def __repr__(self):
        return '<{} at {}>'.format(self.name, hex(id(self)))


    def createPathClient(self, connection):
        self.log.debug('creating client for {}', connection)
        for slot in [0,1]:
            if self.clients[slot] is None:
                return PathClient(self, slot, connection)

        old = self.clients[0]
        self.log.debug('releasing old client instance {}', old)
        path.unregister_client(old)
        old.close()        
        return PathClient(self, 0, connection)
        
    def clients_ready(self):
        if self.clients[0] is None or self.clients[1] is None:
            return False
        self.clients[0].peer = self.clients[1]
        self.clients[1].peer = self.clients[0]
        self.log.info('Clients are ready - roles {}, {}', 
                      self.clients[0].slot,
                      self.clients[1].slot)
        return True
    
    @asyncio.coroutine
    def send_client_roles(self):
        try:
            yield from self.clients[0].send('0')
            yield from self.clients[1].send('1')
        except:
            yield from self.clients[0].close(code=1011)
            yield from self.clients[0].close(code=1011)
        
class Server:
    def __init__(self, loop):
        self.loop = loop
        self.log = logbook.Logger('server')
        self.paths = {}

    @asyncio.coroutine
    def handler(self, connection, path):
        slot = None
        _, path = path.split('/', maxsplit=1)
        
        # Get path instance
        path = self.paths.setdefault(path, Path(self.loop, path))
        self.log.debug('Using path {}', path)
        
        # Create client instance
        client = path.createPathClient(connection)
        
        if path.clients_ready():
            self.loop.create_task(path.send_client_roles())
        
        # Handle client until disconnected or an exception occurred
        try:
            yield from self.handle_client(path, client)
        except websockets.ConnectionClosed:
            self.log.info('Connection closed to {}', client)
        except SignalingError as exc:
            self.log.notice('Closing due to protocol error: {}', exc)
            yield from client.close(code=1002)
        except Exception as exc:
            self.log.exception('Closing due to exception:', exc)
            yield from client.close(code=1011)
        
        # Unregister client
        client.close()
        
    @asyncio.coroutine
    def handle_client(self, path, client):
        # Wait until complete
        tasks = [self.keep_alive(client), self.channel(path, client)]
        tasks = [self.loop.create_task(coroutine) for coroutine in tasks]
        done, pending = yield from asyncio.wait(
            tasks, loop=self.loop, return_when=asyncio.FIRST_EXCEPTION)
        for task in done:
            exc = task.exception()

            # Cancel pending tasks
            for pending_task in pending:
                self.log.debug('Cancelling task {}', pending_task)
                pending_task.cancel()

            # Raise (or re-raise)
            if exc is None:
                self.log.error('Task {} returned unexpectedly', task)
                raise SignalingError('A task returned unexpectedly')
            else:
                raise exc
    
    @asyncio.coroutine
    def keep_alive(self, client):
        try:
            while True:
                self.log.debug('Ping to {}', client)
                try:
                    # Send ping
                    yield from asyncio.wait_for(client.ping(), PING_TIMEOUT)
                except asyncio.TimeoutError:
                    raise SignalingError('Ping timeout')
                else:
                    self.log.debug('Pong from {}', client)

                # Wait
                yield from asyncio.sleep(PING_INTERVAL)
        except asyncio.CancelledError:
            self.log.debug('Ping cancelled')
            
    @asyncio.coroutine
    def channel(self, path, client):
        try:
            while True:
                # Receive message
                message = yield from client.receive()
                length = len(message)
                self.log.info('Received {} bytes from {}', length, client)
                self.log.debug('<< {}', message)
                
                if client.peer is None:
                    self.log.info('Ignoring last message as peer is not available: {}', message)
                    continue
                
                # Send to other client
                self.log.info('Sending {} bytes to {}', length, client.peer)
                self.log.debug('>> {}', message)
                yield from client.peer.send(message)
        except asyncio.CancelledError:
            self.log.debug('Channel cancelled')

def main():
    loop = asyncio.get_event_loop()
    server = Server(loop)
    ws_server = websockets.serve(server.handler, port=9765)
    loop.run_until_complete(ws_server)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    logging_handler = logbook.more.ColorizedStderrHandler()
    with logging_handler.applicationbound():
        main()