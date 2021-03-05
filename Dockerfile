FROM python:3.8

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY Pipfile .
COPY Pipfile.lock .

RUN pip install --upgrade pip && pip install pipenv && pipenv install

COPY auth/ ./auth
COPY .env .

WORKDIR ./auth
EXPOSE 5000/tcp
