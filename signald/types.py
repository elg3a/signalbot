from typing import Optional
from typing import Union

import attr


@attr.s
class Attachment:
    content_type = attr.ib(type=str)
    id = attr.ib(type=str)
    size = attr.ib(type=int)
    stored_filename = attr.ib(type=str)


@attr.s
class Reaction:
    emoji = attr.ib(type=str)
    target_author = attr.ib(type=Union[str, dict])
    target_sent_timestamp = attr.ib(type=int)
    remove = attr.ib(type=bool, default=False)


@attr.s
class Payment:
    note = attr.ib(type=str)
    receipt = attr.ib(type=str)


@attr.s
class Message:
    username = attr.ib(type=str)
    source = attr.ib(type=Union[str, dict])
    text = attr.ib(type=str)
    source_device = attr.ib(type=int, default=0)
    timestamp = attr.ib(type=int, default=None)
    expiration_secs = attr.ib(type=int, default=0)
    is_receipt = attr.ib(type=bool, default=False)
    attachments = attr.ib(type=list, default=[])
    quote = attr.ib(type=str, default=None)
    group = attr.ib(type=dict, default={})
    group_v2 = attr.ib(type=dict, default={})
    reaction = attr.ib(type=Optional[Reaction], default=None)
    payment = attr.ib(type=Optional[Payment], default=None)
