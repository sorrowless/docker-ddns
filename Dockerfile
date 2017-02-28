FROM alpine:latest
MAINTAINER Marcelo Bartsch <marcelo@bartsch.cl>

COPY requirements.txt docker-ddns.py secrets.json docker-ddns.json /ddns/
RUN apk --no-cache add py-pip python3-dev libc-dev gcc docker && pip3 install -r /ddns/requirements.txt && chmod +x /ddns/docker-ddns.py && apk --no-cache del gcc libc-dev python3-dev && apk --no-cache add python3
WORKDIR /ddns
ENTRYPOINT [ "/ddns/docker-ddns.py" ]
