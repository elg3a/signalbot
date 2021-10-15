import json
import logging
import re
import socket
import datetime
from signald import Signal
from typing import List
from signald.types import Message, Reaction, Attachment


class MySignal(Signal):
    def run_chat(self) -> None:

        s = self._get_socket()
        s.send(
            json.dumps(
                {"type": "subscribe", "account": self.username, "version": "v1"}
            ).encode("utf8")
            + b"\n"
        )

        # timeout after 30s to perform other tasks
        s.settimeout(30)

        """Read a socket, line by line."""
        buf = []  # type: List[bytes]

        # flag to indicate if periodic update did run
        did_run_flag = False

        while True:
            try:  # Keyboard interrupt or socket timeout
                char = s.recv(1)
                if not char:
                    raise ConnectionResetError("connection was reset")

                if char == b"\n":
                    line = b"".join(buf)
                    buf = []
                    try:
                        message = json.loads(line.decode())
                    except json.JSONDecodeError:
                        logging.warning("Invalid JSON encountered")

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

                    message = Message(
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
                    )

                    if not message.text:
                        continue

                    for _, regex, func in self._chat_handlers:
                        match = re.search(regex, message.text)
                        if not match:
                            continue

                        try:
                            reply = func(message, match)
                        except Exception as e:  # noqa - We don't care why this failed.
                            logging.warning(repr(e))
                            continue

                        # In case a message came from a group chat
                        group_id = message.group.get("groupId") or message.group_v2.get("id")

                        if reply is not None:
                            if group_id:
                                self.send(recipient_group_id=group_id, text=reply)
                            else:
                                self.send(recipient=message.source, text=reply)

                        break  # only use first match

                else:  # if char != \n
                    buf.append(char)
            # check if automatic messages are to be sent, run the automatic
            # message handler only once between 8 and 9 each day
            except socket.timeout:
                if (datetime.time(8, 0, 0)
                        <= datetime.datetime.now().time()
                        <= datetime.time(9, 0, 0)):
                    if not did_run_flag:
                        for message in self.auto_message_generator():
                            self.send(**message)
                        did_run_flag = True
                else:
                    did_run_flag = False

            except KeyboardInterrupt:
                logging.info("Byebye")
                break

    def auto_message_generator(self) -> List:
        return []
