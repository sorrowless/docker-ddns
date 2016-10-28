#!/usr/bin/env python3
import logging
import docker
import json
import sys
import dns
import dns.tsigkeyring
import dns.update
import dns.query


logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', level=logging.INFO)

configfile = 'dockerddns.json'
tsigfile = 'secrets.json'
tsighandle = open(tsigfile, mode='r')
logging.debug('Loading DNS Key Data')
keyring = dns.tsigkeyring.from_text(json.load(tsighandle))

logging.debug('Loading Config Informaiton')
configfh = open(configfile, mode='r')
config = json.load(configfh)
tsighandle.close()
configfh.close()
client = docker.Client()


def startup():
    containers = []
    logging.debug('Check running containers and update DDNS')
    for container in client.containers():
        containerinfo = container_info(container["Id"])
        if containerinfo:
            dockerddns('start',containerinfo)


def container_info(containerId):
    container = {}
    inspect = client.inspect_container(containerId)
    json.dumps(inspect)
    networkmode = str(inspect["HostConfig"]["NetworkMode"])
    container['hostname'] = inspect["Config"]["Hostname"]
    container['name'] = inspect["Name"].split('/', 1)[1]
    if ((str(networkmode) != 'host') and ('container:' not in networkmode)):
        if (str(networkmode) != 'default'):
            container['ip'] = inspect["NetworkSettings"]["Networks"][networkmode]["IPAddress"]
        else:
            container['ip'] = inspect["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
    else:
        return False
    return container


def dockerddns(action, event, dnsserver=config['dockerddns']['dnsserver'], ttl=60):
    update = dns.update.Update(config['dockerddns']['zonename'], keyring=keyring, keyname=config['dockerddns']['keyname'])
    if (action == 'start' and event['ip'] != '0.0.0.0' ):
        logging.debug('[%s] Updating dns %s , setting %s.%s to %s' % (event['name'], dnsserver, event['hostname'], config['dockerddns']['zonename'],event['ip']))
        update.replace(event['hostname'], ttl, 'A', event['ip'])
    elif (action == 'die' ):
        logging.debug('[%s] Removing entry for %s.%s in %s' % (event['name'], event['hostname'], config['dockerddns']['zonename'], dnsserver))
        update.delete(event['hostname'])
    try:
      response = dns.query.tcp(update, dnsserver, timeout=10)
    except (socket.error, dns.exception.Timeout):
      logging.debug('Timeout updating DNS')
      response = 'Timeout Socket'
      pass
    except dns.query.UnexpectedSource:
      logging.debug('Unexpected Source')
      response = 'UnexpectedSource'
      pass
    except dns.tsig.PeerBadKey:
      logging.debug('Bad Key for DNS, Check your config files')
      response = "BadKey"
      pass

    if response.rcode() != 0: 
      logging.error("[%s] Error Reported while updating %s (%s/%s)" % (event['name'],event['hostname'],dns.rcode.to_text(response.rcode()), response.rcode()))

def process():
    containerinfo = {}
    events = client.events(decode=True)
    for event in events:
        if event['Type'] == "container":
            if event['Action'] == 'start':
                containerinfo = container_info(event['id'])
                if containerinfo:
                    logging.debug("Container %s is starting with hostname %s and ipAddr %s"
                      % (containerinfo['name'],
                         containerinfo['hostname'], containerinfo['ip']))
                    dockerddns(event['Action'],containerinfo)

            elif event['Action'] == 'die':
                containerinfo = container_info(event['id'])
                if containerinfo:
                    logging.debug("Container %s is stopping %s" %
                      (containerinfo['name'],
                       containerinfo['hostname']))
                    dockerddns(event['Action'],containerinfo)

startup()
try:
    process()
except KeyboardInterrupt:
    logging.info('CTRL-C Pressed, GoodBye!')
    sys.exit()
