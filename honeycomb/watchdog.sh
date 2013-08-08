#!/bin/bash
#
# Examples:
#  (1) when starting from ssh shell:
#		nohup /path/to/watchdog.sh >> /path/to/test.log &
#  (2) when starting from /etc/rc.local:
#		/path/to/watchdog.sh >> /path/to/test.log &

HPATH=$PWD/honeycomb.py
echo "$HPATH"

while [ 1 ]
do
COUNT=`ps -ef | grep honeycomb | grep -v grep | wc -l`
#echo "$COUNT"

if [ "$COUNT" -eq "1" ]
then
echo " Okay. honeycomb still running at `date`"
else
echo " FAIL. honeycomb stalled. Restarting at `date`"
exec python $HPATH &
fi

sleep 2
#./honeycomb
done
