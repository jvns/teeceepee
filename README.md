![Build Status](https://travis-ci.org/jvns/teeceepee.png)

teeceepee
=========


This is a tiny TCP stack implemented in pure Python, for fun and learning.

It's built on top of [scapy](http://www.secdev.org/projects/scapy/), which takes care of all the packet parsing and construction. This module handles actually sending and receiving packets.

It isn't capable of *sending* more than one packet's worth of data at a time so it can't make large requests, but it can make GET requests and receive and put together lots of packets.

There is an example of using it to get a webpage in `examples/curl.py`. The example is quite finicky -- it uses ARP spoofing to bypass the kernel's TCP stack, which sometimes results in it just Not Working. Running it a few times sometimes fixes this problem.

```
sudo python examples/curl.py example.com
```

works for me.

It needs to run as root because it needs to use raw sockets.
