#!/bin/bash
sleep 15
export COWRIE_BASEDIR=/home/cowrie/cowrie
cd /home/cowrie/cowrie
source /home/cowrie/cowrie/cowrie-env/bin/activate
authbind --deep /home/cowrie/cowrie/cowrie-env/bin/cowrie start
