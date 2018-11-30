## ChatRoom Version 2
Colin Stevens

### Files included in this directory
* chatroom.py - the main application
* config.json.backup - a known good set of configuration values for the server to use
* config.json - a working copy that the server has overwritten with new user account information
* badconfig.json - a configuration file that is purposefully lacking values, useful for error checking the server code

### What you need to run this
Only need python3 and the following libraries:
- sys
- argparse
- json
- re
- socket
- threading
All should be installed by default and not require any extra installation.

### How to run this
It's as easy as
```
$python3 chatroom.py --server --config <path to config file>
```
for example:
```
$python3 chatroom.py --server --config ./config.json
```
if you are running the chatroom file from the same folder containing the config file.

The same script can be run in client mode by just running it with no arguments:
```
$python3 chatroom.py
```

Additionally, the script uses command line arguments native to python, so usage can be generated with:
```
$python3 chatroom.py --help
```

### Additional
Any additional questions please forward to me at cjsd32@mail.missouri.edu
