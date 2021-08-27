FROM python:3

WORKDIR /usr/licma

COPY . /usr/licma

RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /usr/licma/src