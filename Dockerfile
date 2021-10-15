FROM python:3-alpine
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY cities500.sqlite config.json db.env main.py mysignald.py utils.py ./
ADD signald ./signald
CMD ["python3", "main.py"]
