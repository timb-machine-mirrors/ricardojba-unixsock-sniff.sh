#!/usr/bin/env bash

# https://gist.githubusercontent.com/ranjithum/274b921eed36d2e98c204f43aaf53ca3/raw/8a3c8d875a88416306be46e376bc485af0a76f49/unix-shark
# https://mivehind.net/2018/04/20/sniffing-unix-domain-sockets/
# https://www.humbug.in/2013/sniffing-unix-domain-sockets/
# https://pypi.org/project/unixdump/
# https://github.com/mechpen/sockdump

_usage()
{
    echo -e "\nUsage: $0 \n\
        -u unix domain socket file name\n\
        -w capture file name, Default /tmp/unix_socket_dump.pcap\n\
        -h to display the usage\n"
    exit 1
}

_cleanup()
{
    if ps -p "$socatTcpListener" > /dev/null ;then
        kill -9 "$socatTcpListener"
    fi

    if ps -p "$socatUnixListener" > /dev/null ;then
        kill -9 "$socatUnixListener"
    fi

    if [ -f "$unixSocketFile" ]; then
        rm "${unixSocketFile}"
    fi
    mv "${source_socket}" "${unixSocketFile}"
}

_exit()
{
    echo
    read -p 'Stop Sniffing? (y/n) [Y] >' answer
    case $answer
    in
        [yY]) _cleanup
    ;;
    esac
}

unixSocketFile=
captureDumpFile="/tmp/unix_socket_dump.pcap"
sockatTimeoutInterval=100
wiresharkPort=9888

while getopts "hu:w" arg
do
    case $arg in
        u)
            unixSocketFile=${OPTARG}
            ;;
        w)
            captureDumpFile=${OPTARG}
            ;;
        h)
            _usage
            ;;
    esac
done

if [ -z "$unixSocketFile" ]; then
    _usage
fi

if [ ! -S "$unixSocketFile" ] ; then
    echo "Unix socket file not present, Make sure the server is running"
    exit 1
fi

echo "Capturing data from $unixSocketFile and dumping to $captureDumpFile"

source_socket="$(dirname "${unixSocketFile}")/$(basename "${unixSocketFile}").orig"

# Move socket files
mv "${unixSocketFile}" "${source_socket}"


trap "_exit" SIGINT

# Setup pipe over TCP that we can tap into
socat -t${sockatTimeoutInterval} "TCP-LISTEN:${wiresharkPort},reuseaddr,fork" "UNIX-CONNECT:${source_socket}" &
socatTcpListener=$!
socat -t${sockatTimeoutInterval} "UNIX-LISTEN:${unixSocketFile},mode=777,reuseaddr,fork" "TCP:localhost:${wiresharkPort}" &
socatUnixListener=$!

# Record traffic
tshark -i lo -w "${captureDumpFile}" -F pcapng "dst port ${wiresharkPort} or src port ${wiresharkPort}"