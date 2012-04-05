Twitter DNS
-----------

A DNS alternative for simple access to a network on a dynamic IP.

###Itch###

I have a dynamic IP home network and a server I wanted to access remotely.

I didn't want to pay for a dynamic dns (or manage a free one), nor did
I want to pay for a domain name.

###Scratch###

This code depends on tweepy (a python twitter OAuth package on
[github] [tweepy]), and posts/retrieves the current IP from the
passed-in twitter account username.

[tweepy]:  http://tweepy.github.com/

In daemon (--sleep) mode it updates your IP address on your twitter
feed. If not in sleep mode, then the script will retrieve the IP.

You need to set up your OAuth credentials at
<https://twitter.com/apps> and pass them in as command line options.

For help, simply run the script on the command line.
