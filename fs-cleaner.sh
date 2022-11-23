#!/bin/bash

if [[ ! "$1" =~ ^[0-9]+$ ]] || [[ -z "$2" ]] ; then
    echo "Usage $0 <days> <filelist>"
    exit 1
fi

/usr/bin/awk \
-v DAYS="$1" \
'BEGIN {
    FS=","
    if (DAYS !~ /^[0-9]+$/) {
        print "Error: Specify days back with -v DAYS=<integer>"
        exit 1
    }
    MIN_AGE=(DAYS*24*3600)
}
{ 
    ATIME=$13
    MTIME=$14
    CTIME=$15
    RECENT_TIME=ATIME
    if (MTIME > RECENT_TIME) RECENT_TIME=MTIME
    if (CTIME > RECENT_TIME) RECENT_TIME=CTIME
    CUR_AGE=(systime() - RECENT_TIME);
    if (CUR_AGE > MIN_AGE) print;
}' "$2" >> "older_than_${1}_days.txt"

# Send Email
# ...
