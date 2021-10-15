# Signalbot
An extensible, command based bot interface for the Signal Messenger.
It is build using [signald](https://gitlab.com/thefinn93/signald) and [pysignald](https://gitlab.com/stavros/pysignald).

The Bot implements rudimentary user management using a MongoDB database.
Currently it only has a few sample commands like giving wikipedia summaries, a coin flip and per-user note lists.
There is also basic functionality for recurring notifications in the form of subscriptions to desired services.

As an example of a more advanced feature, the Bot can give weather forecast information for a specified location.
This uses the [Forecast API](https://api.met.no/weatherapi/locationforecast/2.0/documentation) by the Norwegian Meteorological Institute.
To get the required geographical coordinates, a local copy of the [GeoNames](https://www.geonames.org) "cities500" database is used.
It must first be downloaded and converted to SQLite.
This is automated with `geonames-txt2sqlite.py`.

The repository is setup for easy deployment with Docker.
After registering a phone number for use with signal, fill it in `config.json`.
There, also the number of the root user that is allowed to add new users needs to be added.
Then run:
```sh
docker-compose up -d --build
```
(Logs can be viewed with `docker logs --timestamps --follow --tail 10 signalbot-signalbot-1`)
