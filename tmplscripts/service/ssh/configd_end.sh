#!/bin/bash
case $COMMIT_ACTION in
    DELETE)
    invoke-rc.d ssh stop
    ;;
    *)
    vyatta-update-ssh.pl > /etc/ssh/sshd_config
    invoke-rc.d ssh restart
    ;;
esac
