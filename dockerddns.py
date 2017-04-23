#!/usr/bin/env python3
"""sample doc

"""
import logging
import json
import sys
import socket
import docker
import dns
import dns.tsigkeyring
import dns.update
import dns.query


logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', level=logging.INFO)

CONFIGFILE = 'docker-ddns.json'
TSIGFILE = 'secrets.json'


def loadconfig():
    """
    Placeholder
    """
    logging.debug('Loading Config Information')
    configfh = open(CONFIGFILE, mode='r')
    config = json.load(configfh)
    configfh.close()
    logging.debug('Loading DNS Key Data')
    tsighandle = open(TSIGFILE, mode='r')
    config['keyring'] = dns.tsigkeyring.from_text(json.load(tsighandle))
    tsighandle.close()
    return config

def startup(client):
    """
    Placeholder
    """
    logging.debug('Check running containers and update DDNS')
    for container in client.containers.list():
        containerinfo = container_info(json.dumps(container.attrs))
        if containerinfo:
            updatedns('start', containerinfo)


def container_info(container):
    """
    Placeholder
    """
    inspect = json.loads(container)
    container = {}
    networkmode = inspect["HostConfig"]["NetworkMode"]
    container['hostname'] = inspect["Config"]["Hostname"]
    container['name'] = inspect["Name"].split('/', 1)[1]
    if "services" in inspect["Config"]["Labels"]:
        container['srvrecords'] = inspect["Config"]["Labels"]["services"]
        print("%s\n" % (container['srvrecords']))
    if (str(networkmode) != 'host') and ('container:' not in networkmode):
        if str(networkmode) == "default":
            networkmode = "bridge"
        container['ip'] = inspect["NetworkSettings"]["Networks"][networkmode]["IPAddress"]
        container['ipv6'] = \
                inspect["NetworkSettings"]["Networks"][networkmode]["GlobalIPv6Address"]
    else:
        return False
    return container

def updatedns(action, event):
    """
    This function will prepare the information from docker before send it to the dns engine
    """

    config = loadconfig()
    if "ipv6" in event:
        if event['ipv6'] != "" and config['dockerddns']['ipv6replace'] is True:
            ipv6addr = event['ipv6'].replace(config['dockerddns']['intprefix'], \
                                             config['dockerddns']['extprefix'])
            event['ipv6'] = ipv6addr
    if config['dockerddns']['engine'] == "bind":
        return dockerbind(action, event, config)
    elif config['dockerddns']['engine'] == "route53":
        return docker53(action, event, config)
    return False

def docker53(action, event, config):
    """
    This function will update a hosted zone registry in AWS route53
    """
    return True

def dockerbind(action, event, config):
    """
    This will update a zone in a bind dns configured for dynamic updates
    """
    dnsserver = config['dockerddns']['dnsserver']
    ttl = config['dockerddns']['ttl']
    port = config['dockerddns']['dnsport']
    update = dns.update.Update(config['dockerddns']['zonename'],
                               keyring=config['keyring'], keyname=config['dockerddns']['keyname'])

    if "srvrecords" in event:
        srvrecords = event["srvrecords"].split()
        for srv in srvrecords:
            values = srv.split("#")
            print("%s %s\n" % (values, event['hostname']))

    if action == 'start' and event['ip'] != '0.0.0.0':
        update.replace(event['hostname'], ttl, 'A', event['ip'])
        if "ipv6" in event:
            update.replace(event['hostname'], ttl, 'AAAA', event['ipv6'])
            logging.info('[%s] Updating dns %s , setting %s.%s to %s and %s',\
                    event['name'], dnsserver, event['hostname'], config['dockerddns']['zonename'],\
                    event['ip'], event['ipv6'])
        else:
            logging.info('[%s] Updating dns %s , setting %s.%s to %s',\
                    event['name'], dnsserver, event['hostname'],\
                    config['dockerddns']['zonename'], event['ip'])

    elif action == 'die':
        logging.info('[%s] Removing entry for %s.%s in %s', \
                     event['name'], event['hostname'], config['dockerddns']['zonename'],\
                      dnsserver)
        update.delete(event['hostname'])

    try:
        response = dns.query.tcp(update, dnsserver, timeout=10, port=port)
    except (socket.error, dns.exception.Timeout):
        logging.error('Timeout updating DNS')
        response = 'Timeout Socket'
    except dns.query.UnexpectedSource:
        logging.error('Unexpected Source')
        response = 'UnexpectedSource'
    except dns.tsig.PeerBadKey:
        logging.error('Bad Key for DNS, Check your config files')
        response = "BadKey"

    if response.rcode() != 0:
        logging.error("[%s] Error Reported while updating %s (%s/%s)", \
                      event['name'], event['hostname'], \
                       dns.rcode.to_text(response.rcode()), response.rcode())

def process():
    """
    PlaceHolder
    """
    containerinfo = {}
    client = docker.from_env()
    events = client.events(decode=True)
    startup(client)
    for event in events:
        if event['Type'] == "container" and event['Action'] in ('start', 'die'):
            temp = client.containers.get(event['id'])
            containerinfo = container_info(json.dumps(temp.attrs))
            if event['Action'] == 'start':
                if containerinfo:
                    logging.debug("Container %s is starting with hostname %s and ipAddr %s"\
                        , containerinfo['name'],\
                            containerinfo['hostname'], containerinfo['ip'])
                    updatedns(event['Action'], containerinfo)
            elif event['Action'] == 'die':
                if containerinfo:
                    logging.debug("Container %s is stopping %s", \
                        containerinfo['name'],\
                        containerinfo['hostname'])
                    updatedns(event['Action'], containerinfo)

def main():
    """
    Main
    """
    try:
        process()
    except KeyboardInterrupt:
        logging.info('CTRL-C Pressed, GoodBye!')
        sys.exit()

if __name__ == "__main__":
    main()
