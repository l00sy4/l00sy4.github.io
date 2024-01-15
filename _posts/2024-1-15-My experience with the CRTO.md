---
layout: post
title: My experience with the CRTO + review
date: 2024-1-15
categories: [Miscellaneous]
tags: [misc]     
---

Yesterday I passed the Certified Red Team Operator (CRTO) exam and received my badge through e-mail. I decided to pursue this cert in order to solidify my foundations in red teaming as well as get experience with Cobalt Strike. Overall I am very satisfied with what I got, especially considering the price point.In this post I will talk about my experience with the course, exam and community.

### The course

The course is structured around all steps of adversary emulation, familiarizing the student with each stage of the attack lifecycle. It consists of both text-based and video-based modules, a lot of times accompanying eachother. For example, the NTLM Relaying text module is followed by a video in which the instructor, Daniel Duggan, exemplifies the attack.

I consider the biggest strength of this course to be the labor of love behind it. The course gets **regular updates** (once 1-2 months) which ensures that the content stays relevant. In fact, a new module came out right after I finished studying (did I forget to mention that you get lifetime access to the course?)

One of my favourite aspects of the course was the **conciseness**. No scrolling through a bloated 900 page PDF; an usual module showcases the attack, and the concepts behind it. What I also came to appreciate were the OPSEC warnings, where the instructor showed the Kibana logs of the performed technique. The lab has Elastic and Kibana installed, meaning you can always visit the dashboard and see just how stealthy you really were.

All in all, I finished the course in about 2 and a half weeks.

### The lab

The CRTO lab is sandbox-style lab hosted on the Snap Labs platform. Purchasing the lab is optional, but I highly recommend it as it is the **best (legal) way to get experience with Cobalt Strike**. I approached the lab by following along the course, whilst taking notes.

Now Snap Labs work through Apache Guacamole, so you may need to use Edge or a Chromium-based browser for the clipboard to properly work. There is no VPN offered, probably because the Cobalt Strike license doesn't allow it.

### The exam

The exam is also hosted on Snap Labs, and can be scheduled anytime after purchasing the course. You have 48 hours available to use over 4 days, in which you need to capture the 6/8 flags needed to pass. No proctoring is also a plus for me, as I'm not fond of the idea of having some shady corpo watch me in my private space for 48 hours straight.

I think that the exam was very fair as you are tested on what you were actually taught. No unrealistic rabbitholes made to waste time and no weird curveballs; you have all you need in the course. I believe that going back and practicing the TTPs with Defender and AppLocker turned on is enough preparation to get all 8 flags. Make sure to also do the extra challenges mentioned throughout the material and you will most likely succeed.

I started the exam sunday afternoon and got 6 flags by evening. I could have continued with the last 2, but I was a bit sick and called it quits.
