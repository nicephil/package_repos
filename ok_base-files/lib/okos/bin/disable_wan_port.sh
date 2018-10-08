#!/bin/sh

if [ $# -ne 1 ]; then
    echo "Usage: $0 [e0|e1|e2]"
    exit 1
fi


echo "WAN port $1 is disabled."
