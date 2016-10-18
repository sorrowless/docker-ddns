

docker run -it --rm \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v /myconfiglocation/secrets.json:/ddns/secrets.json \
	-v /myconfiglocation/docker-ddns.json:/ddns/docker-ddns.json \
	 mbartsch/ddns:0


in your named.conf you must have:

key "my.key.file." {
  algorithm hmac-md5;
  secret "mykeyfilesecret";
};

zone "myddnszone.mydomain.xtld" IN {
        type master;
        file "dynamic/myddnszone.mydomain.xtld.zone";
        allow-update { key "my.key.file."; };
};


This guide explain in details the needed steps:

https://www.kirya.net/articles/running-a-secure-ddns-service-with-bind/


