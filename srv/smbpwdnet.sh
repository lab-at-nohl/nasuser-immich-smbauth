#!/bin/bash

# echo Type Change or Test
read xCMD
# echo User
read xUSER
# echo Password
read xPWD

RESULT=1
userdbctl user "$xUSER" > /dev/null
if [ $? -ne 0 ]; then
  sleep 5
  exit 99
fi


if [ "$xCMD" == "Test" ]; then
  echo "$xPWD" | smbclient -U $xUSER -t 3 -W WORKGROUP -L localhost > /dev/null
  RESULT=$?
elif [ "$xCMD" == "Change" ]; then
  # echo New Password
  read xNEW
  echo -e "$xPWD\n$xNEW\n$xNEW" | smbpasswd -U $xUSER -s -r localhost > /dev/null
  RESULT=$?
  $RESULT || logger -t smbpwdnet "$xUSER password changed by $REMOTE_ADDR."
fi

if [ $RESULT -ne 0 ]; then
  logger -t smbpwdnet "$xCMD $xUSER failed by $REMOTE_ADDR."
  exit 255
else
  echo "SUCCESS"
fi

exit 0
