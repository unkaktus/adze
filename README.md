## ⛏️adze ⛏️

`adze` is an SSH+SFTP userspace server which authenticates only the running
user by public keys. It enables tooling like rclone work for the systems
that have 2-factor authentication.
Distributed as single static binary, it works anywhere.


### Usage

Loging to the remote, enter your codes, and start adze:

```shell
ssh -L 33456:localhost:33456 cluster
$ adze -p 33456
```

The you can point your tools to `localhost:33456`:
```
ssh -p 33456 localhost
```