---
layout: post
title: My experience with the CRTO + review
date: 2024-1-15
categories: [Miscellaneous, META]
tags: [misc]     
---

Yesterday I passed the Certified Red Team Operator (CRTO) exam and received my badge by email. I decided to pursue this certification to solidify my foundation in red teaming and to gain experience with Cobalt Strike. Overall I am very happy with what I got, especially considering the price. In this article I will talk about my experiences with the course, exam and community.

### The Course

The course is structured around all the steps of adversary emulation, familiarising the student with each stage of the attack lifecycle. It consists of both text-based and video-based modules, often in conjunction with each other. For example, the text module on NTLM Relaying is followed by a video of the instructor, Daniel Duggan, demonstrating the attack.

I think the greatest strength of this course is the labour of love behind it. The course is updated regularly (once every 1-2 months), which ensures that the content remains relevant. In fact, a new module came out just after I finished (did I forget to mention that you get lifetime access to the course?).

One of my favourite aspects of the course was the conciseness. No scrolling through a bloated 900 page PDF; a standard module shows the attack and the concepts behind it. I also appreciated the OPSEC warnings where the instructor showed the Kibana logs of the technique being performed. The lab has Elastic and Kibana installed, so you can always visit the dashboard and see how stealthy you really were.

All in all, I finished the course in about two and a half weeks.

### The community

CRTO students can join the Zero-Point Security Discord server, where you can ask questions, get help with troubleshooting, or just hang out. I found the discord to be a great help in finding solutions to some of the problems I encountered in the lab.

### The lab

The CRTO Lab is a sandbox-style lab hosted on the Snap Labs platform. Purchasing the lab is optional, but I highly recommend it as it is the best (legal) way to get experience with Cobalt Strike. I approached the lab by following the course while taking notes.

Snap Labs run on Apache Guacamole, so you may need to use Edge or a Chromium-based browser for the clipboard to work properly. There is no VPN provided, presumably because the Cobalt Strike licence doesn't allow it.

### The exam

The exam is also hosted on Snap Labs and can be scheduled at any time after purchasing the course. You have 48 hours over 4 days to capture the 6/8 flags required to pass. The fact that there is no proctoring is also a plus for me, as I don't like the idea of some shady corpo watching me in my private space for 48 hours.

I thought the exam was very fair as you are tested on what you have actually been taught. No unrealistic rabbit holes to waste time and no weird curve balls; you have everything you need in the course. I think going back and practising the TTPs with Defender and AppLocker turned on is enough preparation to get all 8 flags. Make sure you also do the extra challenges mentioned throughout the material and you will most likely succeed.

I started the exam on Sunday afternoon and got 6 flags by the evening. I could have gone on for the last 2 but I felt a bit sick and stopped.
