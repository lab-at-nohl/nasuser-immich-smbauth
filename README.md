# Combine Immich with your local Linux used as NAS

This repository provides bash scripts that help you administrating a NAS with immich, whereas the files beside pictures/videos are shared by Samba. 
It is tested with openSuse but chould work with other systems using systemd as well.

What was needed?

1. **smbpwd-daemon** A daemon to authenticate Immich logins against Samba accounts (using systemd managed sockets)
2. **podman-immich** Easy management of Immich containers, here with podman due to glueing into filesystem (access user's files by supplementary group) 
3. **nasuser** The tool for adding, removing and more of local users, including automated creation/deletion of Immich accounts

Overview:

## Prerequisite: Prepare disks for BTRFS storage

### Create base subvolumes for UUID of storage mirrored disks (RAID 1)

#### Show UUID of e.g. /dev/sdb & /dev/sdc
`blkid`

#### Create new subvolumes
```
mount UUID=1e8bc2a6-4fd1-4496-9327-62be185b029e /mnt/
btrfs subvolume /mnt/@home
btrfs subvolume /mnt/@srv
btrfs subvolume set-default /mnt/@home
umount /mnt/* /mnt/
```

#### Remove the /home that was mounted by os installer on sys disk!
`umount /home`

And remove from /etc/fstab, see below.

### Mount Subvolumes

#### Add new UUID to /etc/fstab; remove already existing /home on sys disc
```
UUID=1e8bc2a6-4fd1-4496-9327-62be185b029e  /home                   btrfs  defaults                      0  0
UUID=1e8bc2a6-4fd1-4496-9327-62be185b029e  /srv                    btrfs  subvol=@/srv                  0  0
```

#### Make sure it works
```
mount -a
btrfs subvolume list /srv
btrfs subvolume list /home
```

#### Enjoy BTRFS magic, snapper is also needed later
```
zypper in snapper
snapper -c srv create-config /srv/
```

## Download ZIP of this repo to /srv and install scripts
```
wget wget https://github.com/lab-at-nohl/nasuser-immich-smbauth/archive/refs/heads/main.zip
unzip main.zip
rm main.zip
```

```
cp nasuser-immich-smbauth-4ff33a3/srv/* /usr/local/
chmod +x /usr/local/sbin/*
cp nasuser-immich-smbauth-4ff33a3/systemd/system/smbpwd-daemon* /etc/systemd/system/
```

In file `/etc/systemd/system/smbpwd-daemon@.service`: Change `/srv/sbin/smbpwd-daemon.sh` to `/usr/local/sbin/smbpwd-daemon` (where we installed the daemon)

```
systemctl start smbpwd-daemon.socket
systemctl enable smbpwd-daemon.socket
```

## Install Samba shares for /home/<users>
```
zypper in samba samba-client samba-winbind avahi
cp nasuser-immich-smbauth-4ff33a3/samba/smb.conf /etc/samba/

systemctl start smb nmb
systemctl start avahi-daemon

systemctl enable smb nmb
systemctl enable avahi-daemon
```

## Initial installation of Immich

### Prepare the host for Immich files
```
groupadd -g 299 -r immich
useradd -M -g 299 -u 299 -N -d /home immich
zypper in podman crun
```

### Select Hw acceleration for Immich (note the minus)

In file `/usr/local/sbin/podman-immich` set to `IMMICH_ML_HW=-openvino` if you use Intel. 

### Define fake-Domain for emails to be authed by Samba (e.g. newuser@nas)

In file `/usr/local/share/immich-getsmbpwdnet.js`: Change `YOURDOMAINNAME` to e.g. `nas` (or anything that identifies your server in conjunction with the local users)

### Enjoy podman downloading and running Immich 

#### podman-immich reuses existing images. After podman pull new-image... it is your future update tool, too

`podman-immich` (this tool brings up all the necessary servers, storing its data under `/srv/immich` for default). 

#### Troubleshooting, download images separately (I use Intel = openvino, in doubt omit suffix)

Try one of these, e.g. download image in advance, check folder structure or see logs...

```
podman pull ghcr.io/immich-app/immich-machine-learning:release-openvino
podman pull ghcr.io/immich-app/immich-server:release
ls -l /srv/immich/
podman logs --tail=50 -f Immich-Server
```

### NAS User management

#### Login to your http://server:[5000], Create initial User aka Admin

First user will be Admin. Do not use a local account like admin@nas (see below), use a real mailadress instead. You may need it later for password reset etc. 

For the magic of `nasuser` management you need to have Admin's API key. You can create one, go to Settings -> API Keys -> name it e.g. nasuser. 

In file `/usr/local/sbin/nasuser` add it to `IMMICH_API_KEY=XXX...`.  

#### Create local user; Login Immich and change password

```
nasuser --help

nasuser add user1
```

Login to your Immich-Instance with the fake-domain, which you have changed from YOURDOMAINNAME to e.g. nas (see above). 
A patched Immich-Server tries to authenticate all users with `@nas` against the Samba password database, that builds on local users. 

Login: 
`http://server:[5000]` -> user1@nas -> note the password that `nasuser` has set and printed out!

#### Log

- Initial commit 2025-01-05, small fixes in the following days
