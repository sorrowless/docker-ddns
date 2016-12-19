
# Hot To Run
docker run -it --rm \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v /myconfiglocation/secrets.json:/ddns/secrets.json \
	-v /myconfiglocation/docker-ddns.json:/ddns/docker-ddns.json \
	 mbartsch/ddns:0

# Config Needed

## docker-ddns.json 

{
  "dockerddns": {
    "dnsserver" : "my.dns.server",
    "dnsport"   : 53,
    "keyname"   : "my.dns.key",
    "zonename"  : "dynamic.mydomain.ntld"
  }
}

dnsserver = hostname of bind
dnsport   = port used by bind , you can change it if 53 is blocked
keyname   = the keyname
zonename  = ddns zone

## secrets.json


{"my.key.file":"base64_encrypted_key"}

left side  = key name as in named.conf
right side = mykeyfilesecret in base64 , same as in named.conf
 
## bind setup
in your named.conf you must have:

```
key "my.key.file" {
  algorithm hmac-md5;
  secret "mykeyfilesecret";
};

zone "myddnszone.mydomain.xtld" IN {
        type master;
        file "dynamic/myddnszone.mydomain.xtld.zone";
        allow-update { key "my.key.file"; };
};
```


This guide explain in details the needed steps:

https://www.kirya.net/articles/running-a-secure-ddns-service-with-bind/


