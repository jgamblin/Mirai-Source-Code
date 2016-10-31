# Mirai BotNet
Leaked Linux.Mirai Source Code for Research/IoT Development Purposes

Uploaded for research purposes and so we can develop IoT and such.

See "ForumPost.txt" or [ForumPost.md](ForumPost.md) for the post in which it
leaks, if you want to know how it is all set up and the likes.

## Nematode branch

This is a purely academic research project intended to show a proof of concept 
anti-worm worm (or nematode) for the types of vulnerabilities exploited by
Mirai (default Telnet creds). The idea is to show that devices can be patched by
a worm that deletes itself after changing the password to something device-
specific or random. Such a tool could theoretically be used to reduce the attack
surface. This is meant to only be tested in closed research environments. Use of 
this software is at your own risk.

Developed directly from Mirai. Community improvements welcomed.

## Requirements
* gcc
* golang
* electric-fence
* mysql-server
* mysql-client

## Credits

[Anna-senpai](https://hackforums.net/showthread.php?tid=5420472)

## Disclaimer

This repository is for academic purposes, the use of this software is your
responsibility.


