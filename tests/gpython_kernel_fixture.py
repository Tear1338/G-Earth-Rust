import time
import threading

deadline = time.monotonic() + 10
while ext.connection_info is None and time.monotonic() < deadline:
    time.sleep(0.01)
assert ext.connection_info is not None
assert not is_closed()
seen = []
release = threading.Event()
ext.on_event("double_click", release.set)


def modify(message):
    value = message.packet.read_int()
    if value == 13:
        message.is_blocked = True
    else:
        message.packet.replace_int(6, value + 100)
    seen.append(value)


intercept(Direction.TO_SERVER, modify, "TestOutgoing")
intercept(Direction.TO_CLIENT, modify, "TestIncoming")
send_to_server(HPacket("TestInjection", 17))
send_to_client(HPacket(92, 18))
while len(seen) < 3 and time.monotonic() < deadline:
    time.sleep(0.01)
assert seen == [5, 13, 7], seen
send_to_server(HPacket(93, len(seen)))
# Rust sends this event only after receiving the interception response. Merely
# observing the callback's list update can race the response IPC write.
assert release.wait(10), "host did not confirm receipt of interception response"
assert seen == [5, 13, 7, 99], seen
