# h4ckb0x
A simple, docker based, hacking environment FTW.

## Build

```bash
$ make
```

## Run

```bash
# define a project dir
$ export HACKBOX_PROJECT_DIR="/myProjectDir"
# define a list of env variables you would like to take set into the h4ckb0x (for example $IP as your primary CTF target)
$ echo "IP=127.0.0.1" >> $HOME/.h4ckb0x.env
$ h4ckb0x
```
