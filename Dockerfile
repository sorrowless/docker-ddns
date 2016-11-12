FROM alpine:latest
MAINTAINER Marcelo Bartsch <marcelo@bartsch.cl>

RUN apk --no-cache add py-pip python3-dev libc-dev gcc docker
RUN mkdir /ddns
COPY requirements.txt /ddns
RUN pip3 install -r /ddns/requirements.txt
COPY docker-ddns.py /ddns
COPY secrets.json /ddns
COPY docker-ddns.json /ddns
RUN chmod +x /ddns/docker-ddns.py
WORKDIR /ddns
ENTRYPOINT [ "/ddns/docker-ddns.py" ]
