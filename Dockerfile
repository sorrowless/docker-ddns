FROM alpine:latest
MAINTAINER Marcelo Bartsch <marcelo@bartsch.cl>

COPY requirements.txt dockerddns.py secrets.json docker-ddns.json /ddns/
RUN apk --no-cache add python3 py-pip python3-dev libc-dev gcc docker && pip3 install -r /ddns/requirements.txt && chmod +x /ddns/dockerddns.py && apk --no-cache del gcc libc-dev python3-dev 
WORKDIR /ddns
ENTRYPOINT [ "/ddns/dockerddns.py" ]
