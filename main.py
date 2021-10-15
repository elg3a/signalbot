#!/usr/bin/env python3
# encoding:utf8
"""An extensible, command based bot interface for the Signal Messenger.

"""
import functools
import json
import logging
import os
import random
import time
import uuid
import wikipedia
from datetime import datetime, timedelta
from mysignald import MySignal
from pymongo import MongoClient
from utils import parse_weather_location

workdir = os.getcwd() + "/"

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    handlers=[
        # logging.FileHandler(filename=workdir + "signalbot.log"),
        logging.StreamHandler()
    ]
)

logging.info("### Starting... ###")

filetime = datetime.fromtimestamp(os.path.getmtime("cities500.sqlite"))
if datetime.now() - filetime > timedelta(days=30):
    logging.warning("GeoNames database is outdated. You can update it using "
                    "`geonames-txt2sqlite.py`")

with open(workdir + "config.json", "r") as fh:
    config = json.load(fh)
USERNAME = config["username"]
ROOT = config["root"]
db_user = os.environ.get("MONGO_INITDB_ROOT_USERNAME")
db_password = os.environ.get("MONGO_INITDB_ROOT_PASSWORD")

client = MongoClient(f"mongodb://{db_user}:{db_password}@db:27017/")
USERS = client.signald.users
logging.info("### mongoDB ###")
logging.info(f"server version: {client.server_info()['version']}")
logging.info(f"available databases: {client.list_database_names()}")

s = MySignal(USERNAME, socket_path="/signald/signald.sock")

logging.info("Notifying Root")
s.send(text="I am up!", recipient=ROOT)
logging.info("Ready!")


def authenticated(func):
    """Decorator to authenticate user against database and provide command,
    body and user to wrapped function."""
    @functools.wraps(func)
    def wrapper(message, match):
        uid = message.source["number"]

        if not USERS.count_documents({"_id": uid}, limit=1) and uid != ROOT:
            text = f"Unauthorized access attempt by {uid}"
            logging.warning(text)
            s.send(text, recipient=ROOT)
            # do not even reply to unauthorized users
            return None
        # ignore newly received messages older than 10 minutes
        elif datetime.now().timestamp() - (message.timestamp / 1000) > 600:
            logging.warning(f"Missed message from {uid}: {message.text}")
            return None
        else:
            # extract user, command and message body
            user = USERS.find_one({"_id": uid})
            msg = message.text
            logging.info(uid + ": " + msg)
            msglist = msg.split(" ")
            command = msglist[0].lower()
            body = msglist[1:]
            return func(command, body, user)
    return wrapper


def auto_message_generator():
    messages = []
    for user in USERS.find({"groups": "notes_subscribers"}):
        notes = user["notes"]
        if len(notes) == 0:
            text = "You do not have any notes."
        else:
            text = "Your notes:\n" + "\n".join(
                [f"{num + 1}. {note}" for num, note in enumerate(notes)])
        messages.append({"recipient": user["_id"], "text": text})
    return messages


@s.chat_handler("^(hi|hello).*$")
@authenticated
def hello(command, body, user):
    return "Hello there!"


@s.chat_handler("^ping.*$")
@authenticated
def ping(command, body, user):
    return "pong"


@s.chat_handler("^coin.*$")
@authenticated
def coin(command, body, user):
    return random.choice(["heads", "tails"])


@s.chat_handler("^(wiki|wikipedia).*$")
@authenticated
def wiki(command, body, user):
    try:
        summary = wikipedia.summary("".join(body), auto_suggest=False)
        page = wikipedia.page("".join(body))
        page.title
        page.url
        return page.title + "\n" + summary + "\n" + page.url
    except wikipedia.DisambiguationError as e:
        return str(e)


@s.chat_handler("^help.*$")
@authenticated
def help(command, body, user):
    # TODO: generate this automatically from docstrings
    return (
        "hello - say hello\n"
        "ping - receive pong\n"
        "notes [[clear|add|remove] <item>] - make a note\n"
        "wiki[pedia] - get wikipedia summary and article link"
    )


@s.chat_handler("^add.*$")
@authenticated
def add(command, body, user):
    # only ROOT can add users, else pretend the command does not exist
    if user["_id"] != ROOT:
        return f"I'm sorry {user['name']}, I'm afraid I can't do that."
    if len(body) != 2:
        return "usage: add [name] [number]"

    USERS.insert_one({"_id": body[1], "name": body[0].capitalize(),
                      "groups": ["users"], "notes": []})
    s.send(text=(
        "Hi, I am a simple Signal Bot. "
        "You have been added to my users list. "
        "Type help to get information on the available commands."
    ), recipient=body[1])
    time.sleep(1)
    return f"Added {body[1]} as {USERS.find_one({'_id': body[1]})['name']}"


@s.chat_handler("^notes.*$")
@authenticated
def notes(command, body, user):
    if len(body) == 0:  # by default list notes
        notes = user["notes"]
        if len(notes) == 0:
            return "You do not have any notes."
        else:
            return "Your notes:\n" + "\n".join(
                   [f"{i + 1}. {note}" for i, note in enumerate(notes)])
    if body[0] == "clear":
        USERS.update_one({"_id": user["_id"]}, {"$set": {"notes": []}},
                         upsert=False)
        return "Cleared all notes!"
    if body[0] == "add":
        if len(body) == 1:
            return "Please specify an item to add."
        USERS.update_one({"_id": user["_id"]},
                         {"$push": {"notes": " ".join(body[1:])}},
                         upsert=False)
        return "Item added!"
    if body[0] == "remove":
        try:
            index = int(body[1]) - 1
        except (ValueError, IndexError):
            return (
                "Please specify the number of the entry you want to remove."
            )
        notes = user["notes"]
        if index not in range(len(notes)):
            return f"Your list has no item {index + 1}."
        tmp_value = str(uuid.uuid4())
        USERS.update_one({"_id": user["_id"]},
                         {"$set": {"notes." + str(index): tmp_value}})
        USERS.update_one({"_id": user["_id"]},
                         {"$pull": {"notes": tmp_value}},
                         upsert=False)
        return "Item removed!"
    return "Please specify *add* [item] or *remove* [item]."


@s.chat_handler("^subscribe.*$")
@authenticated
def subscribe(command, body, user):
    if len(body) != 1:
        return (
            "You can subscribe to the following lists to get regular "
            "updates by specifying the corresponding term as an option:\n"
            "notes - list of your notes every morning"
        )
    if body[0] not in ["weather", "notes"]:
        return "Please specify one of the available subscriptions."
    if body[0] + "_subscribers" in user["groups"]:
        return f"You are already subscribed to {body[0]}."
    USERS.update_one({"_id": user["_id"]},
                     {"$push": {"groups": body[0] + "_subscribers"}},
                     upsert=False)
    return f"You have subscribed to {body[0]}."


@s.chat_handler("^unsubscribe.*$")
@authenticated
def unsubscribe(command, body, user):
    subscriptions = [x[:-12] for x in user["groups"] if x.endswith(
        "_subscribers")]
    if len(body) == 0:
        return "You are subscribed to:\n" + "    \n".join(subscriptions)
    if body[0] not in subscriptions:
        return "You are not subscribed to that group."
    USERS.update_one({"_id": user["_id"]},
                     {"$pull": {"groups": body[0] + "_subscribers"}},
                     upsert=False)
    return f"You have unsubscribed from {body[0]}."


@s.chat_handler("^weather.*$")
@authenticated
def weather(command, body, user):
    # TODO: Assume default location as last used one if len(body) == 0
    return parse_weather_location("".join(body))


@s.chat_handler("")
@authenticated
def catch_all(command, body, user):
    return f"I'm sorry {user['name']}, I'm afraid I can't do that."


if __name__ == "__main__":
    s.auto_message_generator = auto_message_generator
    s.run_chat()
