#!/bin/bash

docker run -it -v $PWD:/root/work ttsiodras/asn1scc bash -c "cd /root/work; mono /usr/local/share/asn1scc/asn1.exe -Ada -ACN $1.asn $1.acn; chown `id -u`:`id -g` *"
