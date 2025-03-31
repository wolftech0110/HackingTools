# Consolidated Script from AOC2024_Day1 Project
# Originally created by alexander-utkov for the HTB challenge (https://app.hackthebox.com/challenges/295).
# There you can find the ic2kp client and a sample capture.
# All functionality from submodules has been integrated into this single file.
# External dependencies: pyshark, Crypto, termcolor, colorama
# Tested only in kali linux in a venv
# Author: KaliMaxx_

import argparse
import math
import subprocess
import hashlib
from dataclasses import dataclass
from Crypto.Cipher import AES
from termcolor import colored
from colorama import init
import pyshark


def prefilter_capture(input_pcap, output_pcap):
    """
    Filters the input pcap file to include only TCP packets with a length > 0.

    :param input_pcap: Path to the original capture file.
    :param output_pcap: Path to save the filtered capture.
    """
    filter_expression = "tcp && tcp.len > 0"
    tshark_command = [
        "tshark",
        "-r",
        input_pcap,  # Input pcap file
        "-Y",
        filter_expression,  # Display filter
        "-w",
        output_pcap,  # Output filtered file
    ]
    try:
        subprocess.run(tshark_command, check=True)
        print(f"Filtered pcap saved to {output_pcap}")
        print("\nAnalyzing file...")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Tshark filtering failed: {e}")


__help__ = """common problems:

verbose levels:

1) -v: extra information;
2) -vv: packets and advances.

example: analyze.py -c capture.pcap -s S3cr3tP@ss -vv

"""


def get_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=__help__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c",
        default="capture.pcap",
        dest="capture",
        help="path to capture file from wireshark",
        metavar="CAPTURE",
        type=str,
    )
    parser.add_argument(
        "-s",
        default="S3cr3tP@ss",
        dest="secret",
        help="ic2kp session shared secret",
        metavar="SECRET",
        type=str,
    )
    parser.add_argument(
        "-i",
        default=None,
        dest="initial",
        help="initial packet index",
        metavar="INDEX",
        type=int,
    )
    parser.add_argument(
        "-v",
        action="count",
        default=0,
        dest="verbose",
        help="everything in detail",
    )
    parser.add_argument(
        "--signature",
        default="5890ae86f1b91cf6298395711dde580d",
        dest="signature",
        help="ic2kp magic hex signature, e.g. 5890...580d",
        metavar="HEX",
        type=str,
    )
    return parser.parse_args()


def read_initializations(context, verbose: int = 0):
    term = context.get_data(sender=MASTER)  # environment variable
    argp = context.get_data(sender=MASTER)  # ioctl 3'th param
    TBD = context.get_data(sender=MASTER)
    if verbose > 0:
        info(f"putenv('TERM={term.decode()}');")
        info(f"ioctl(..., ..., argp={hexdigest(argp)});")
        info(f"TBD: {TBD}")


# --- Module: core/commands/reverse_shell.py ---
__all__ = ["reverse_shell"]


def reverse_shell(context, verbose: int = 0, **kwargs) -> None:
    read_initializations(context, verbose)

    cout = str()
    cin = str()
    while True:
        try:
            pack = context.get_data()
            if pack is None:
                break
            sender, binary = pack
            text = binary.decode()
            if sender == SLAVE:
                cout += text
            else:
                cin += text
        except Exception as e:
            raise
    newline = "← "
    print(colored(newline + cin.replace("\r", f"\n{newline}"), "dark_grey"))
    newline = "→ "
    print(newline + cout.replace("\n", f"\n{newline}"))


# --- Module: analyze.py ---
# Decrypts traffic generated by ic2kp (rekobee).

__all__ = ["analyze"]


commands = {
    b"\x01": ("upload file", None),
    b"\x02": ("download file", None),
    b"\x03": ("reverse shell", reverse_shell),
}


def analyze(capture, secret: str, signature: str, **kwargs):
    """
    Decrypts traffic from capture and prints as plain text.

    See the command-line help for the meaning of the arguments and the contents
    of kwargs.
    """
    context = step_1(capture, secret, **kwargs)
    assert isinstance(context, Context)
    try:
        step_2(context, signature, **kwargs)
    except Exception as e:
        warning(
            (
                f"CHAP failed. At best, this means that the wrong shared secret "
                f"(now '{secret}') has been set. Does your ic2kp MD5 match that "
                f"of 'eec8680ebb6926b75829acec93bb484d'? If not so, then the "
                f"default secret AND a MAGIC SIGNATURE (now '{signature}') may be "
                f"different."
            )
        )
        raise
    while True:
        command = context.get_data(sender=MASTER)
        if command is None:
            break
        if len(command) != 1:
            raise ProtocolError("A command code of length 1 is expected.")
        if command not in commands:
            raise ProtocolError(f"Unknown command code {hexdigest(command)}.")
        display_name, entry_function = commands[command]
        info(f"Handling '{display_name}' command.")
        if entry_function is None:
            raise NotImplementedError(("This command has not yet been implemented."))
        entry_function(context, **kwargs)
    info("Done.")


# --- Module: core/chap.py ---
# Provide steps for handshake (CHAP) analysis.

__all__ = ["step_1", "step_2"]


def find_initial_index(capture):
    """
    Finds the index of the initial packet.

    :param      capture:  The capture.
    :type       capture:  pyshark.FileCapture

    :returns:   Returns the index if found; otherwise, a negative number.
    :rtype:     bytes
    """
    # for index, packet in enumerate(capture):
    #     if int(packet.tcp.len) == 40:
    #         return index
    # return -1

    for index, packet in enumerate(capture):
        try:
            if (
                hasattr(packet, "tcp")
                and hasattr(packet.tcp, "len")
                and int(packet.tcp.len) == 40
            ):
                return index
        except AttributeError:
            print(
                f"Skipping packet at index {index}: No TCP layer or missing attributes."
            )
            continue
    return -1


def get_initial_index(capture, initial: int = None):
    """
    Gets the index of the initial TCP packet.

    :param      capture:  The capture.
    :type       capture:  pyshark.FileCapture
    :param      initial:  User-specified initial index, defaults to None
    :type       initial:  int, optional

    :returns:   The initial index.
    :rtype:     int
    """
    if initial is None:
        initial = find_initial_index(capture)
        if initial < 0:
            raise ValueError(
                "Initial packet not found. Ensure the capture contains valid TCP packets."
            )
        success(f"Found the initial packet at index {initial}.")
    else:
        packet = capture[initial]
        if not (
            hasattr(packet, "tcp")
            and hasattr(packet.tcp, "len")
            and int(packet.tcp.len) == 40
        ):
            raise ValueError(
                f"The user-specified initial packet at index {initial} has an invalid payload length."
            )
    return initial


def show_participants(packets_filter):
    info(
        "Participants:",
        f"CNC: {packets_filter.master_address}:{packets_filter.master_port}",
        f"Slave: {packets_filter.slave_address}:{packets_filter.slave_port}",
        sep="\n",
        style="list",
    )


def show_encryption(key_1, key_2, iv_1, iv_2, verbose: int = 0):
    info(
        "Encryption (from the client's point of view):",
        f"AES(key={hexdigest(key_1)}, iv={hexdigest(iv_1)}) for sending;",
        f"AES(key={hexdigest(key_2)}, iv={hexdigest(iv_2)}) for receiving.",
        sep="\n",
        style="enum" if verbose > 1 else "list",
    )


def step_1(capture, secret: str, **kwargs) -> None:
    """
    Step 1: initial packet.

    The server sends a initial packet (40 bytes).
    """
    initial = kwargs.get("initial", None)
    verbose = kwargs.get("verbose", 0)

    initial = get_initial_index(capture, initial)

    # The server sends two hashes to the client:
    #
    # - `sha1({timeval_1}{pid})`
    # - `sha1({timeval_2}{pid + 1})`
    #
    # Where timeval is a linux-specific structure.
    packet = capture[initial]
    hashes = data(packet)
    salt_1 = hashes[:20]
    salt_2 = hashes[20:]

    # They are then used as salt and key in two aes contexts.
    #
    # 6 @ 00001d55  aes_init(&aes_ctx_1, encryption_secret, &aes_salt_2);
    # 7 @ 00001d67  aes_init(&aes_ctx_2, encryption_secret, &aes_salt_1);
    #
    # 15 @ 00001401  *(aes_ctx + 0x408) = *salt
    # 16 @ 0000141c  *(aes_ctx + 0x418) = ...
    #
    # The code base is shared, so the server uses it the same way, but the salts
    # are in direct order, and vice versa to the client. Note that we only need
    # decryption.
    key_1 = truncate_to_128(sha1(secret.encode() + salt_2))
    key_2 = truncate_to_128(sha1(secret.encode() + salt_1))
    iv_1 = truncate_to_128(salt_2)  # 0xfb28 send_mutable_xor (part of aes_ctx_1)
    iv_2 = truncate_to_128(salt_1)  # 0xe628 recv_mutable_xor (part of aes_ctx_2)
    # Probably AES CBC was made by hand on top of EBC.
    aes_1 = AES.new(key_1, AES.MODE_CBC, iv=iv_1)
    aes_2 = AES.new(key_2, AES.MODE_CBC, iv=iv_2)

    filter = PacketsFilter(packet)
    if verbose > 0:
        show_participants(filter)
    if verbose > 1:
        payload = dump(hashes, size=20, highlights=((0, 16), (20, 36)))
        info("Initial packet payload (salts highlighted):", payload, sep="\n")
    if verbose > 0:
        show_encryption(key_1, key_2, iv_1, iv_2, verbose)

    return Context(
        aes_1=aes_1,
        aes_2=aes_2,
        capture=capture,
        current_packet=initial,
        packets_filter=filter,
        verbose=verbose,
    )


def step_2(context, signature: str, **kwargs) -> None:
    """
    Step 2: bilateral challenge.

    The server sends a challenge - encrypted 16 bytes of magic signature, and if
    it matches the client's magic signature, then the client sends it back.
    """
    if isinstance(signature, str):
        signature = blob(signature)
    elif not isinstance(signature, bytes):
        raise TypeError("The signature is not bytes or hexadecimal string.")

    challenge_1 = context.get_data(MASTER)
    if challenge_1 != signature:
        # FIXME: Probably not. Correctness is determined by the version of the
        # client, but I just pulled it out to the argument. Otherwise, the
        # server may spam (?) the initial packets.
        raise HandshakeError("The server sent an invalid magic signature.")
    success("The server is authenticated by the client.")

    challenge_2 = context.get_data(SLAVE)
    if challenge_1 != challenge_2:
        # The server will categorically refuse the connection.
        raise HandshakeError("The client sent an invalid magic signature.")
    success("The client is authenticated by the server.")  # most likely


# --- Module: core/encryption.py ---
# Provides cryptography for the ic2kp protocol.

"""Packet structure:

+--------------+---------+--------------------+----------+
| Content size | Content | AES block padding  | HMAC     |
+--------------+---------+--------------------+----------+
| 2 bytes      | ← bytes | up to 15 bytes     | 20 bytes |
+--------------+---------+--------------------+----------+
| AES 128 (CBC)                               | Raw      |
+--------------+---------+--------------------+----------+
"""

__all__ = ["decrypt"]


def get_aes_context(context, sender: str):
    if sender not in (SLAVE, MASTER):
        raise ValueError(f"Unknown sender '{sender}'.")
    if context.verbose > 1:
        ctx_no = 1 if sender == SLAVE else 2
        info(f"The packet will be decrypted with #%d AES context." % ctx_no)
    return context.aes_1 if sender == SLAVE else context.aes_2


def get_content_size(header: bytes, verbose: int) -> int:
    binary = header[:2]
    result = int.from_bytes(binary, "big")  # endianness is not little
    if verbose > 1:
        info(
            "Packet header (and initial buffer):",
            dump(header, highlights=((0, 2),)),
            sep="\n",
        )
    if result < 0 or result > 4096:
        # Something unverifiable is wrong:
        #
        # 1) we do the decryption in a wrong order;
        # 2) someone sends malicious data (diff ic2kp version).
        raise ProtocolError(
            (
                f"Invalid size packet ({result}) received. it is more likely "
                f"that the shared secret is wrong."
            )
        )
    return result


def get_initial_buffer(header: bytes) -> bytes:
    return header[2:]  # 14 bytes after the content size in the same AES block


def decrypt(context, data: bytes, sender: str):
    """
    Dangerously decrypts data.

    It is recommended to use `core.models.Context.get_data` instead.

    The IV will be overwritten with this data, and if not in the order that the
    server was sent, then you will get a broken context due to AES CBC nature.

    You can pass more than one packet through the data parameter, but the sender
    must be the same. Useful for concatenated TCP packets.

    :param   context:  The decryption context.
    :type    context:  models.Context
    :param      data:  The binary data packets to decrypt.
    :type       data:  bytes
    :param    sender:  The required sender - MASTER or SLAVE ('filters.py').
    :type     sender:  str

    :returns:   Returns the decrypted data for the current batch of packets.
    :rtype:     Generator[bytes, None, None]
    """
    aes_ctx = get_aes_context(context, sender)

    header = aes_ctx.decrypt(data[:16])
    content_size = get_content_size(header, context.verbose)
    buffer = get_initial_buffer(header)

    packet_size = None
    if content_size <= 14:
        packet_size = 2 + 14  # content_size + buffer with padding
        buffer = buffer[:content_size]  # remove padding
    else:
        # Computing the end of encrypted packet in the data.
        packet_size = math.ceil((2 + content_size) / 16) * 16
        remain_data = data[2 + 14 : packet_size]  # without initial buffer
        buffer = buffer + aes_ctx.decrypt(remain_data)[: content_size - 14]
    hmac = data[packet_size : packet_size + 20]

    if len(hmac) != 0x14:
        raise ProtocolError(f"Packet signature ({hexdigest(hmac)}) of invalid size.")
    # TODO: The client will reject the packet if the hmac is invalid.
    # The HMAC check ensures that the decryption order is correct.

    if context.verbose > 1:
        info(
            "Packet:",
            f"size: {content_size};",
            f"HMAC: {hexdigest(hmac)}.",
            sep="\n",
            style="list",
        )
        info("Content:", dump(buffer), sep="\n")

    yield buffer

    # TCP packets can be nested.
    next_packet = data[packet_size + 20 :]
    if len(next_packet) > 0:
        if context.verbose > 1:
            info("The TCP packet contains a nested ic2kp packet.")
        for buffer in decrypt(context, next_packet, sender):
            yield buffer


# --- Module: core/models/filters.py ---
__all__ = ["PacketsFilter", "MASTER", "SLAVE"]


MASTER = "master"
SLAVE = "slave"


class PacketsFilter:

    # Provides information about the client (infected) and the server (CNC).

    def __init__(self, packet):
        """
        Constructor that extracts information from the initial packet.

        :param      packet:  The initial packet.
        :type       packet:  pyshark.packet.packet.Packet
        """
        self.master_address = str(packet.ip.src)
        self.slave_address = str(packet.ip.dst)
        self.master_port = int(packet.tcp.srcport)
        self.slave_port = int(packet.tcp.dstport)
        self._comparable_master = set(
            (
                self.master_address,
                self.master_port,
            )
        )
        self._comparable_slave = set(
            (
                self.slave_address,
                self.slave_port,
            )
        )
        self._comparable = set(
            (
                self.master_address,
                self.master_port,
                self.slave_address,
                self.slave_port,
            )
        )

    def __call__(self, packet, sender: str = None) -> bool:
        """
        Checks if the packet belongs to the participants.

        :param      packet:  The packet.
        :type       packet:  pyshark.packet.packet.Packet
        :param      sender:  The requested side to send the packet or None.
        :type       sender:  str

        :returns:   Returns true if so; otherwise, false.
        :rtype:     bool
        """
        if sender is None:
            comparable = set(
                (
                    str(packet.ip.src),
                    int(packet.tcp.srcport),
                    str(packet.ip.dst),
                    int(packet.tcp.dstport),
                )
            )
            return comparable == self._comparable
        comparable = set(
            (
                str(packet.ip.src),
                int(packet.tcp.srcport),
            )
        )
        if sender == MASTER:
            return comparable == self._comparable_master
        if sender == SLAVE:
            return comparable == self._comparable_slave
        raise NotImplementedError(f"Unknown sender '{sender}'.")

    def identify_sender(self, packet) -> str:
        for sender in (MASTER, SLAVE):
            if self(packet, sender):
                return sender
        raise ImplementationError("Automatic sender identification failed.")


# --- Module: core/models/context.py ---
__all__ = ["Context"]


@dataclass
class Context:

    # Provides information about the decryption process, TCP and ic2kp packets.

    aes_1: AES
    aes_2: AES
    capture: pyshark.FileCapture
    current_packet: int
    packets_filter: PacketsFilter
    verbose: int

    def __post_init__(self):
        self._decrypted = list()
        self._last_sender = None

    def __del__(self):
        try:
            self.capture.close()
        except Exception as e:
            warning("Failed to gracefully close capture.")
            if self.verbose != 0:
                raise

    @property
    def tcp_packet(self):
        try:
            return self.capture[self.current_packet]
        except KeyError:
            return None

    def advance(self, sender: str = None):
        """
        Safely advances the current_packet index.

        Note that a TCP packet can contain more than one ic2kp packet.

        :param    sender:  MASTER, SLAVE, or None.
        :type     sender:  str

        :returns: Returns the current TCP packet itself or None.
        :rtype:   pyshark.packet.packet.Packet
        """
        try:
            while True:
                self.current_packet += 1
                packet = self.capture[self.current_packet]

                # Check if the packet has the TCP layer and a valid length
                if not hasattr(packet, "tcp") or not hasattr(packet.tcp, "len"):
                    if self.verbose > 1:
                        warning(
                            f"Skipping non-TCP packet at index {self.current_packet}."
                        )
                    continue

                if int(packet.tcp.len) == 0:
                    if self.verbose > 1:
                        warning(
                            f"Skipping TCP packet with zero length at index {self.current_packet}."
                        )
                    continue

                # Check sender filter
                if not self.packets_filter(packet, sender):
                    if self.verbose > 1:
                        warning("The non-empty packet was ignored.")
                    continue

                if self.verbose > 1:
                    info(
                        (
                            f"Advance to packet {self.current_packet} (sent by "
                            f"{sender})."
                        )
                    )
                return packet
        except KeyError:
            return None

    def get_data(self, sender: str = None) -> bytes:
        """
        Decrypts the next ic2kp packet (probably in the same TCP packet).

        :param    sender:  MASTER, SLAVE or None to auto identify.
        :type     sender:  str

        :returns:   Returns the decrypted data or None. If the sender was
                    automatically identified, return a tuple like (sender,
                    decoded); otherwise, just decoded.
        :rtype:     bytes | tuple[str, bytes]
        """
        if len(self._decrypted) == 0:

            # One or more ic2kp packets from a TCP packet.
            packets = self.advance(sender)
            if packets is None:
                return None

            liable = sender
            if sender is None:
                liable = self.packets_filter.identify_sender(packets)
            self._last_sender = sender

            decrypted = decrypt(self, data(packets), sender=liable)
            if self._last_sender is None:
                self._decrypted.extend([(liable, dat) for dat in decrypted])
            else:
                self._decrypted.extend(list(decrypted))
        elif sender != self._last_sender:
            # Probably outside of the function, the packet is expected to be
            # sent (and decrypted) by the sender, but in fact the packet can
            # be sent by both the client and the server.

            if sender != self.packets_filter.identify_sender(self.tcp_packet):
                raise ImplementationError(
                    (
                        f"Undefined behaviour: not fetched all available ic2kp "
                        f"packets as {self._last_sender}, but started fetching "
                        f"as {sender}."
                    )
                )
        return self._decrypted.pop(0)


def data(packet) -> bytes:
    """
    Gets the packet data as bytes.

    :param      packet:  The packet.
    :type       packet:  pyshark.packet.packet.Packet

    :returns:   Returns packet data.
    :rtype:     bytes
    """
    return blob(packet.DATA.data)


def truncate_to_128(sha1: bytes):
    """
    Truncates SHA1 (160 bit) to AES 128 (bit) how is it done by the executable.

    The executable implicitly truncates the hash via `(char*)int128_t`, which is
    before volatile int32_t and another large buffer.

    00001ce1  uint64_t client_init(int32_t connection, char* encryption_secret)

    2 @ 00001d21  int128_t aes_salt_1 = buffer
    3 @ 00001d2b  int32_t var_48_1 = buffer_after_16b  // volatile;
    7 @ 00001d67  aes_init(aes_ctx: &aes_ctx_2, secret: encryption_secret, salt: &aes_salt_1)

    00001385  void* aes_init(int32_t* aes_ctx, char* secret, char* salt)

    :param      sha1:  The SHA1 hash.
    :type       sha1:  bytes

    :returns:   Returns AES 128 key.
    :rtype:     bytes
    """
    return sha1[:16]  # excellent


# --- Module: core/utils/encoding.py ---
# Provides converters to work with data representations.


__all__ = ["blob", "hexdigest"]


def blob(string: str) -> bytes:
    """
    Converts HEX string to bytes, i.e. blob("000102) → b"\x00\x01\x02".

    :param      string:  The HEX string.
    :type       string:  str

    :returns:   Returns the binary equivalent.
    :rtype:     bytes
    """
    array = list(string)
    pairs = zip(array[0::2], array[1::2])
    hexes = map(lambda p: str().join(p), pairs)
    result = bytes.fromhex(" ".join(hexes))
    return result


def hexdigest(data) -> str:
    """
    The opposite of the blob function, i.e. hexdigest(b"\x01\x02") → "0102".
    """
    if isinstance(data, int):
        representation = str(hex(data))  # 0x1
        truncated = representation[2:]  # 1
        justed = truncated.rjust(2, "0")  # 01
        return justed
    elif isinstance(data, bytes):
        interim = map(hexdigest, data)
        result = str().join(interim)
        return result
    raise TypeError("The data is neither bytes nor int.")


# --- Module: core/utils/printing.py ---
# Provides pretty printing features.

__all__ = ["colored", "info", "warning", "success", "error", "dump"]

try:
    init()
    del init
except ImportError:

    def colored(message: str, color: str = str()) -> str:
        return message


def get_markered_list(label_len: int, body: str) -> str:

    tab = " " * (label_len + 1)
    marker = "• "
    result = body.replace("\n", "\n" + tab + marker)
    return result


def get_enumerated_list(label_len: int, body: str) -> str:

    tab = " " * (label_len + 1)
    body_lines = body.split("\n")
    result_lines = [
        body_lines[0],
    ]
    for enumerator, part in enumerate(body_lines[1:], 1):
        result_lines.append(f"{tab}{enumerator}) {part}")
    result = "\n".join(result_lines)
    return result


styles = {
    "list": get_markered_list,
    "enum": get_enumerated_list,
}


def pprint(label: str, color: str, *objects, **kwargs) -> None:
    separator = kwargs.get("sep", " ")
    end = kwargs.get("end", "\n")
    style = kwargs.get("style", None)

    head = colored(label, color)  # colored prefix like [info]
    body = separator.join(map(str, objects))  # message after prefix

    if style is not None:
        if style not in styles:
            raise ValueError(f"Unknown pprint style '{style}'.")
        formatter = styles[style]
        label_len = len(label)  # head has extra ANSI escape codes
        body = formatter(label_len, body)

    print(f"{head} {body}", end=end)


def get_pprint_wrapper(label, color):
    def wrapped(*args, **kwargs):
        pprint(label, color, *args, **kwargs)

    return wrapped


info = get_pprint_wrapper("[info]", "light_blue")
warning = get_pprint_wrapper("[warning]", "light_yellow")
success = get_pprint_wrapper("[ ok ]", "light_green")
error = get_pprint_wrapper("[error]", "light_red")


def chunks(iterable, size: int) -> list:
    for index in range(0, len(iterable), size):
        yield iterable[index : index + size]


def escaped(iterable):
    bad_charset = ("\x0a", "\x0b", "\x0c", "\x0d")
    for char in iterable:
        if char not in bad_charset:
            yield char
        else:
            dummy_escaped = str(char.encode())  # "b'\x0b'"
            hex_escaped = dummy_escaped[2:-1]  # "\x0b"
            yield str(hex_escaped)


def dump(data: bytes, size: int = 16, highlights: tuple = ()) -> str:
    """
    Represents the data in dump format, i.e.:

    ```
    [data] 00 01 02 03 44 75 6d 70 | \x00\x01\x02\x03Dump
    [0x08] a5                      | ¥
    ```

    :param          data:  The binary data to represent.
    :type           data:  bytes
    :param          size:  The column width.
    :type           size:  int
    :param    highlights:  A segments to highlight in format `(start, end)`.
    :type     highlights:  tuple[tuple[int, int]]

    :returns:   Returns the dump as a string with ANSI escape codes.
    :rtype:     str
    """
    codes = hexdigest(data)  # "000102"
    pairs = zip(codes[0::2], codes[1::2])  # ('0', '0', '0'), ('0', '1', '2')
    codes = [str().join(pair) for pair in pairs]  # ["00", "01", "02"]
    chars = list(map(chr, data))  # ['\x00', '\x01', '\x02']

    lines = list()
    prefix = "data"
    codes = chunks(codes, size)
    chars = chunks(chars, size)
    for line_codes, line_chars in zip(codes, chars):
        colored_line_codes = list()
        offset = len(lines) * size
        for index, code in enumerate(line_codes):
            color = "light_grey"
            for start, end in highlights:
                code_index = index + offset
                if code_index >= start and code_index < end:
                    color = "light_yellow"
                    break
            colored_line_codes.append(colored(code, color))
        justed_codes = " ".join(colored_line_codes)
        justed_codes += " " * (size - len(colored_line_codes)) * 3
        escaped_chars = " ".join(escaped(line_chars))
        lines.append(
            (
                colored("[%s]", "dark_grey")
                + " "
                + colored("%s", "light_grey")
                + colored(" | ", "dark_grey")
                + colored("%s", "light_blue")
            )
            % (prefix, justed_codes, escaped_chars)
        )
        prefix = "0x" + hexdigest(size * len(lines))
    result = "\n".join(lines)
    return result


# --- Module: core/utils/hashing.py ---
# Provides hash functions.

__all__ = ["sha1"]


def sha1(data: bytes) -> bytes:
    interim = hashlib.sha1(data)
    result = interim.digest()
    return result


if __name__ == "__main__":
    args = get_args()

    # Pre-filter the input capture file
    filtered_capture = "filtered_capture.pcap"
    prefilter_capture(args.capture, filtered_capture)

    # Reload the filtered capture as a FileCapture object
    args.capture = pyshark.FileCapture(filtered_capture)

    try:
        analyze(**vars(args))
    except Exception as e:
        print(str(e))
        if args.verbose != 0:
            raise
