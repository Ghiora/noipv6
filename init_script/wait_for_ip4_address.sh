#!/bin/sh

# Get the wlan interface
INTERFACE=eth0


# Wait till we have an ipv4 address on the wan port
while true
do
	# the last grep is because awk does not normally return an error is $2 is not found..
	# And I do not want to use awk tricks to fix it. 
	IPV4_ADDR=`ip -4 a show dev ${INTERFACE} |grep inet |awk '{print $2}' | grep "\."`
	ret=$?
	echo IPV4_ADDR=${IPV4_ADDR} >>/tmp/noipv6_waiting_for_ipv4_address
	if [ $ret -ne 0 ]
	then
		echo "sleep"
		echo "sleeping till we have an ipv4 address" >>/tmp/noipv6_waiting_for_ipv4_address
		sleep 30
	else
		echo "We found an ip4 address on ${INTERFACE}  ${IPV4_ADDR}" >>/tmp/noipv6_waiting_for_ipv4_address
		break
	fi
done

nohup /sbin/noipv6 >>/tmp/noipv6 2>&1 &




