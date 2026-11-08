FROM python:3.10-slim
ARG API_KEY=supersecret123
ADD https://example.com/setup.sh /tmp/setup.sh
FROM ubuntu:latest
USER root
RUN pip install -r requirements.txt
