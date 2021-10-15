import json
import random
import re
import socket
from typing import Iterator
from typing import List
from typing import Union

from deprecated import deprecated

from .types import Attachment
from .types import Message
from .types import Payment
from .types import Reaction

# We'll need to know the compiled RE object later.
RE_TYPE = type(re.compile(""))


def readlines(s: socket.socket) -> Iterator[bytes]:
    """Read a socket, line by line."""
    buf = []  # type: List[bytes]
    while True:
        char = s.recv(1)
        if not char:
            raise ConnectionResetError("connection was reset")

        if char == b"\n":
            yield b"".join(buf)
            buf = []
        else:
            buf.append(char)


class Signal:
    def __init__(self, username, socket_path="/var/run/signald/signald.sock"):
        self.username = username
        self.socket_path = socket_path
        self._chat_handlers = []

    def _get_id(self):
        """Generate a random ID."""
        return "".join(
            random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10)
        )

    def _get_socket(self) -> socket.socket:
        """Create a socket, connect to the server and return it."""
        # Support TCP sockets on the sly.
        if isinstance(self.socket_path, tuple):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.socket_path)
        return s

    def _send_command(self, payload: dict, block: bool = False):
        s = self._get_socket()
        msg_id = self._get_id()
        payload["id"] = msg_id
        s.recv(1024)  # Flush the buffer.
        s.send(json.dumps(payload).encode("utf8") + b"\n")

        if not block:
            return

        response_data = {}
        response = s.recv(4 * 1024)
        for line in response.split(b"\n"):
            if msg_id.encode("utf8") not in line:
                continue

            data = json.loads(line)

            if data.get("id") != msg_id:
                continue

            if data["type"] == "unexpected_error":
                raise ValueError("unexpected error occurred")

            if data.get("error_type") == "RequestValidationFailure":
                raise ValueError(data.get("error"))

            response_data = data

        return response_data

    def register(self, server, voice=False, captcha=None):
        """
        Register the given number.

        voice: Whether to receive a voice call or an SMS for verification.
        captcha: Add captcha token if available (retrieved e.g. via
                 https://signalcaptchas.org/registration/generate.html).
        """
        payload = {
            "type": "register",
            "account": self.username,
            "voice": voice,
            "server": server,
            "version": "v1",
        }

        if captcha:
            payload["captcha"] = captcha

        return self._send_command(payload)

    def verify(self, code: str):
        """
        Verify the given number by entering the code you received.

        code: The code Signal sent you.
        """
        payload = {
            "type": "verify",
            "account": self.username,
            "code": code,
            "version": "v1",
        }
        return self._send_command(payload)

    def receive_messages(self) -> Iterator[Message]:
        """Keep returning received messages."""
        s = self._get_socket()
        s.send(
            json.dumps(
                {"type": "subscribe", "account": self.username, "version": "v1"}
            ).encode("utf8")
            + b"\n"
        )

        for line in readlines(s):
            try:
                message = json.loads(line.decode())
            except json.JSONDecodeError:
                print("Invalid JSON")

            if (
                message.get("type") != "IncomingMessage"
                or message["data"].get("data_message") is None
            ):
                # If the message type isn't "message", or if it's a weird message whose
                # purpose I don't know, return. I think the weird message is a typing
                # notification.
                continue

            message = message["data"]
            data_message = message.get("data_message", {})
            reaction = None
            if "reaction" in data_message:
                react = data_message.get("reaction")
                reaction = Reaction(
                    react.get("emoji"),
                    react.get("targetAuthor"),
                    react.get("targetSentTimestamp"),
                    react.get("remove"),
                )

            payment = None
            if "payment" in data_message:
                payment = Payment(
                    note=data_message["payment"].get("note"),
                    receipt=data_message["payment"].get("receipt"),
                )

            yield Message(
                username=message["account"],
                source=message["source"],
                text=data_message.get("body"),
                source_device=message["source_device"],
                timestamp=data_message.get("timestamp"),
                expiration_secs=data_message.get("expiresInSeconds"),
                is_receipt=message["type"] == "RECEIPT",
                group=data_message.get("group", {}),
                group_v2=data_message.get("groupV2", {}),
                attachments=[
                    Attachment(
                        content_type=attachment["contentType"],
                        id=attachment["id"],
                        size=attachment["size"],
                        stored_filename=attachment["storedFilename"],
                    )
                    for attachment in data_message.get("attachments", [])
                ],
                reaction=reaction,
                payment=payment,
            )

    @deprecated(version="0.1.0", reason="Use 'send' with keyword argument 'recipient'")
    def send_message(
        self,
        recipient: Union[str, dict],
        text: str,
        block: bool = True,
        attachments: List[str] = [],
    ) -> None:
        """
        Send a message.

        recipient:   The recipient's phone number, in E.123 format as string or wrapped in an address structure.
        text:        The text of the message to send.
        block:       Whether to block while sending. If you choose not to block, you won't get an exception if there
                     are any errors.
        attachments: List of full qualified filenames to add as attachments.
                     The files must be readable by the signald daemon.
        """
        return self.send(
            text, recipient=recipient, block=block, attachments=attachments
        )

    @deprecated(
        version="0.1.0", reason="Use 'send' with keyword argument 'recipient_group_id'"
    )
    def send_group_message(
        self,
        recipient_group_id: str,
        text: str,
        block: bool = False,
        attachments: List[str] = [],
    ) -> None:
        """
        Send a group message.

        recipient_group_id: The base64 encoded group ID to send to.
        text:               The text of the message to send.
        block:              Whether to block while sending. If you choose not to block, you won't get an exception if
                            there are any errors.
        attachments:        List of full qualified filenames to add as attachments.
                            The files must be readable by the signald daemon.
        """
        return self.send(
            text,
            recipient_group_id=recipient_group_id,
            block=block,
            attachments=attachments,
        )

    def send(
        self,
        text: str,
        recipient: Union[str, dict] = None,
        recipient_group_id: str = None,
        block: bool = True,
        attachments: List[str] = [],
    ) -> None:
        """
        Send a message.

        text:               The text of the message to send.
        recipient:          The recipient's phone number, in E.123 format as string or wrapped in an address structure.
                            Required if recipient_group_id is None.
        recipient_group_id: The base64 encoded group ID to send to. Required if recipient is None.
        block:              Whether to block while sending. If you choose not to block, you won't get an exception
                            if there are any errors.
        attachments:        List of full qualified filenames to add as attachments.
                            The files must be readable by the signald daemon.
        """
        payload = {
            "type": "send",
            "username": self.username,
            "messageBody": text,
            "attachments": [{"filename": filename} for filename in attachments],
            "version": "v1",
        }
        if recipient:
            payload["recipientAddress"] = recipient
        if recipient_group_id:
            payload["recipientGroupId"] = recipient_group_id

        return self._send_command(payload, block)

    def send_read_receipt(self, recipient, timestamps, block: bool = True) -> None:
        """
        Send a message-was-read receipt.

        This triggers the checkmark on the receipient side indicating the message has been read.

        recipient:  The recipient's phone number, in E.123 format as string or wrapped in an address structure. Required.
        timestamps: List of message timestamps to acknowledge. These come from the `timestamp` field on received messages.
                    This is the way Signal identifies individual messages.
        block:      Whether to block while sending. If you choose not to block, you won't get an exception
                    if there are any errors.
        """
        if not isinstance(timestamps, list):
            timestamps = [timestamps]

        payload = {
            "type": "mark_read",
            "account": self.username,
            "to": recipient,
            "timestamps": timestamps,
            "version": "v1",
        }
        return self._send_command(payload, block)

    def send_payment_receipt(
        self,
        recipient_address: str,
        receiver_receipt: str,
        note: str,
        block: bool = True,
    ) -> None:
        """
        Send a payment receipt.

        recipient_address: The Signal address for the recipient of this payment receipt.
        receiver_receipt: A base64-encoded mobilecoin payment receipt
        """
        payload = {
            "type": "send_payment",
            "version": "v1",
            "account": self.username,
            "address": recipient_address,
            "attachments": [],
            "payment": {
                "receipt": receiver_receipt,
                "note": note,
            },
        }
        return self._send_command(payload, block)

    def set_profile(
        self,
        display_name,
        mobilecoin_address=None,
        avatar_filename=None,
        block: bool = True,
    ):
        """
        Set our profile information.

        display_name:       Profile name
        mobilecoin_address: Mobilecoin base64-encoded public address
        avatar_filename:    Path to an avatar filename (must be accessible by signald)
        """
        payload = {
            "type": "set_profile",
            "version": "v1",
            "account": self.username,
            "name": display_name,
        }
        if mobilecoin_address:
            payload.update(mobilecoin_address=mobilecoin_address)
        if avatar_filename:
            payload.update(avatarFile=f"/signald/{avatar_filename}")
        print(payload)
        return self._send_command(payload, block)

    def get_profile(self, recipient):
        """
        Get the profile information of a given receipient.

        This command alwasy blocks since it makes no sense to call it without waiting for the reply.

        recipient:          The recipient's phone number, in E.123 format as string or wrapped in an address structure.
        """
        payload = {
            "type": "get_profile",
            "version": "v1",
            "address": recipient,
            "account": self.username,
        }
        response = self._send_command(payload, block=True)
        return response["data"]

    def react(
        self,
        reaction: Reaction,
        recipient: Union[str, dict] = None,
        recipient_group_id: str = None,
        block: bool = True,
    ) -> None:
        """
        React to a message.

        reaction:           The reaction to a message.
        recipient:          The recipient's phone number, in E.123 format as string or wrapped in an address structure.
                            Required if recipient_group_id is None.
        recipient_group_id: The base64 encoded group ID to send to. Required if recipient is None.
        block:              Whether to block while sending. If you choose not to block, you won't get an exception if there
                            are any errors.
        """
        payload = {
            "type": "react",
            "username": self.username,
            "reaction": {
                "emoji": reaction.emoji,
                "targetAuthor": reaction.target_author,
                "targetSentTimestamp": reaction.target_sent_timestamp,
                "remove": reaction.remove,
            },
        }
        if recipient:
            payload["recipientAddress"] = recipient
        if recipient_group_id:
            payload["recipientGroupId"] = recipient_group_id

        return self._send_command(payload, block)

    def chat_handler(self, regex, order=100):
        """Register a chat handler function with a regex."""
        if not isinstance(regex, RE_TYPE):
            regex = re.compile(regex, re.I)

        def decorator(func):
            self._chat_handlers.append((order, regex, func))
            # Use only the first value to sort so that declaration order doesn't change.
            self._chat_handlers.sort(key=lambda x: x[0])
            return func

        return decorator

    def run_chat(self):
        """Start the chat event loop."""
        for message in self.receive_messages():
            if not message.text:
                continue

            for _, regex, func in self._chat_handlers:
                match = re.search(regex, message.text)
                if not match:
                    continue

                try:
                    reply = func(message, match)
                except:  # noqa - We don't care why this failed.
                    continue

                if not isinstance(reply, tuple):
                    stop = True
                    reaction = None
                if len(reply) == 2:
                    stop, reply = reply
                    reaction = None
                elif len(reply) == 3:
                    stop, reply, reaction = reply

                # In case a message came from a group chat
                group_id = message.group.get("groupId") or message.group_v2.get("id")

                if reply is not None:
                    if group_id:
                        self.send(recipient_group_id=group_id, text=reply)
                    else:
                        self.send(recipient=message.source, text=reply)

                if reaction is not None:
                    r = Reaction(reaction, message.source, message.timestamp)
                    if group_id:
                        self.react(recipient_group_id=group_id, reaction=r)
                    else:
                        self.react(recipient=message.source, reaction=r)

                if stop:
                    # We don't want to continue matching things.
                    break
