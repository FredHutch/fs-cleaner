fs-cleaner
==========

fs-cleaner deletes files based on last access or modification time. The most common use case is managing persistent scratch file systems, for example in high performance computing environments. Scratch file systems contain temporary, machine generated data that can be deleted after use. 


    user@box1:~/py$ ./fs-cleaner.py --help
    usage: fs-cleaner [-h] [--debug] [--email-notify EMAIL] [--warn-days WARNDAYS]
                  [--days DAYS] [--remove-appledoubles] [--folder FOLDER]

    clean out old files on a scratch file system and notify file owners.

    optional arguments:
    -h, --help            show this help message and exit
    --debug, -g           show the actual shell commands that are executed (git,
                          chmod, cd)
    --email-notify EMAIL, -e EMAIL
                          notify this email address of any error
    --warn-days WARNDAYS, -w WARNDAYS
                          warn user x days before removal of file (default: 0
                          days = deactivated)
    --days DAYS, -d DAYS  remove files older than x days (default: 1461 days or
                          4 years)
    --remove-appledoubles, -a
                          immediately remove AppleDoubles at the source.
    --folder FOLDER, -f FOLDER
                          search this folder and below for files to remove


