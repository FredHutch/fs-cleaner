#!/bin/bash

# TODO: Use pwalk to generate file list if not provided

if [[ ! "$1" =~ ^[0-9]+$ ]] || [[ -z "$2" ]] ; then
    echo "Usage $0 <days> <filelist>"
    exit 1
fi

OUTFILE="older_than_${1}_days.txt"

if [[ -e "$OUTFILE" ]] ; then
    rm "$OUTFILE"
fi

awk \
-v DAYS="$1" \
'BEGIN {
    FS=","
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
    if (CUR_AGE > MIN_AGE) print(strftime("%m/%d/%Y %H:%M:%S", RECENT_TIME), $4);
}' "$2" | sort -k "1,2" >> "$OUTFILE"

# Send Email (no list of files sent in production due to size limits)
mail \
    -s "Files older than ${1} days" \
    "hschuber@fredhutch.org" \
<<< $(readlink -f "$OUTFILE")$'\n'$(cat "$OUTFILE")
