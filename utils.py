import datetime
import logging
import requests
import sqlite3
from functools import lru_cache, wraps


def getEmoji(ID):
    ID = ID.replace("sleet", "snow")
    if ID.endswith("_polartwilight"):
        ID = ID[:-len("_polartwilight")]
    if ID.endswith("_night") and ID != "clearsky_night":
        ID = ID[:-len("_night")]

    if ID in ["clearsky"]:
        return u"\U00002600"  # ☀
    if ID == "clearsky_night":
        return u"\U0001F319"  # 🌙
    if ID == "cloudy":
        return u"\U00002601"  # ☁
    if ID == "fair":
        return u"\U0001F324"  # 🌤
    if ID == "partlycloudy":
        return u"\U0001F325"  # 🌥
        # return u"\U000026C5" # ⛅
    if ID == "fog":
        return u"\U0001F32B"  # 🌫
    if ID.endswith("rain"):
        return u"\U0001F327"  # 🌧
    if ID.endswith("snow"):
        return u"\U0001F328"  # 🌨
    if ID.endswith("showersandthunder"):
        return u"\U0001F329"  # 🌩
    if ID.endswith("andthunder"):
        return u"\U000026C8"  # ⛈
    if ID.endswith("showers"):
        return u"\U0001F326"  # 🌦
    logging.info("unknown emoji")
    return " "


def parse_weather_location(location):
    location = location.lower()
    if "," in location:
        location = location.split(",")
        city = location[0].strip().lstrip()
        code = location[1].strip().lstrip()
        query = (
            f'SELECT * FROM cities500 WHERE "country code" = "{code.upper()}" '
            f'AND ( lower(name) = "{city}" OR lower(asciiname) = "{city}" )')
    else:
        query = (
            f'SELECT * FROM cities500 WHERE '
            f'lower(name) = "{location}" OR lower(asciiname) = "{location}"')

    with sqlite3.connect("cities500.sqlite") as con:
        cur = con.cursor()
        locations = cur.execute(query).fetchall()

    num_locations = len(locations)
    if num_locations == 0:
        return "Unknown location"
    elif num_locations == 1:
        ret = get_weather(locations[0])
        return ret
    else:
        return "Locations:\n" + "\n".join(
            [f"{i + 1}. {loc[1]}, {'None' if loc[5] is None else loc[5]}"
             for i, loc in enumerate(locations)])


# caching https://realpython.com/lru-cache-python/
def timed_lru_cache(seconds, maxsize):
    def wrapper_cache(func):
        func = lru_cache(maxsize=maxsize)(func)
        func.lifetime = datetime.timedelta(seconds=seconds)
        func.expiration = datetime.datetime.utcnow() + func.lifetime

        @wraps(func)
        def wrapped_func(*args, **kwargs):
            print(func.cache_info())
            if datetime.datetime.utcnow() >= func.expiration:
                func.cache_clear()
                func.expiration = datetime.datetime.utcnow() + func.lifetime
            return func(*args, **kwargs)

        return wrapped_func

    return wrapper_cache


@timed_lru_cache(maxsize=16, seconds=3600)
def get_weather(location):
    """location is tuple including coordinates
    (id, "Name", "Ascii Name", lat, long, "country code", elevation)"""

    lat = location[3]
    long = location[4]
    el = location[6]
    headers = {"User-Agent": "signalbot github.com/elg3a/signalbot"}
    apiurl = "https://api.met.no/weatherapi/locationforecast/2.0/compact"
    # Round to 4 decimal places: https://developer.yr.no/doc/GettingStarted/
    params = f"?lat={lat:.4f}&lon={long:.4f}"
    if el:
        params += f"&altitude={int(el)}"
    response = requests.get(apiurl + params, headers=headers)
    data = response.json()
    x = data["properties"]["timeseries"]

    updated_at = datetime.datetime.strptime(
        data["properties"]["meta"]["updated_at"], "%Y-%m-%dT%H:%M:%SZ")
    updated_at = updated_at.replace(tzinfo=datetime.timezone.utc).astimezone()

    # 6 hours forecast
    labels, temperatures, precipitations, symbols = [], [], [], []
    for i in range(0, len(x), 6):
        # temperatures are given every hour at the hour
        # precipitation and weather symbol is given for a timespan
        time = datetime.datetime.strptime(x[i]["time"], "%Y-%m-%dT%H:%M:%SZ")
        time = time.replace(tzinfo=datetime.timezone.utc).astimezone()
        labels.append(time)
        temperatures.append(
            float(x[i]["data"]["instant"]["details"]["air_temperature"]))
        precipitations.append(
            x[i]["data"]["next_6_hours"]["details"]["precipitation_amount"])
        symbols.append(getEmoji(
            x[i]["data"]["next_6_hours"]["summary"]["symbol_code"]))
        if len(symbols) == 5:
            break
    b = " ▏▎▍▌▋▊▉█"
    bars = ["".join([b[min(8, max(0, int(p * 10) - 8 * col))] for col in range(
            int(max(precipitations) / 8) + 1)]) for p in precipitations]
    msg = f"Weather {location[1]} from {updated_at:%H:%M}\n"
    msg += "\n".join([f"{t.hour:02d} | {T:>2}°C {p:>3}mm {bar} {s}"
                      for t, T, p, bar, s in zip(labels, temperatures,
                                                 precipitations, bars,
                                                 symbols)])
    # detailed 24h precipitation
    precipitations = []
    for i in range(len(x)):
        precipitations.append(
            x[i]["data"]["next_1_hours"]["details"]["precipitation_amount"])
        if len(precipitations) == 24:
            break
    b = " ▁▂▃▄▅▆▇█"
    bars = ["".join([b[min(8, max(0, int(p * 10) - 8 * col))]
                     for p in precipitations])
            for col in range(int(max(precipitations * 10) / 8) + 1)]
    msg += "\n\n" + "\n".join(bars)

    return msg


if __name__ == "__main__":
    print(parse_weather_location("berlin, de"))
