# server-status-python
One script server status monitor over web written in python

<img src="https://raw.githubusercontent.com/somik123/server-status-python/main/screenshot.png">

### Installation

Download to your server:
```
wget https://raw.githubusercontent.com/somik123/server-status-python/main/server.py
```

Start it up on port 9888:
```
python3 server.py 9888
```
> **Note:** If no port is provided, server will start up on port 9808

To start the server up on system reboot, edit your crontabs:

```
crontab -e
```

If the full path of the file is `/home/somik/status/server.py`, add to the bottom of the file:
```
@reboot python3 /home/somik/status/server.py 9888 > /home/somik/status/logs.txt 2>&1 &
```

