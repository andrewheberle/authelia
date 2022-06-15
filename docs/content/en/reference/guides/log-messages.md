---
title: "Log Messages"
description: "A collection of log message reference information"
lead: "This section contains log message references for Authelia."
date: 2022-06-09T18:25:02+10:00
draft: false
images: []
menu:
  reference:
    parent: "guides"
weight: 220
toc: true
---

## Request Header Too Large

The `request header too large` error with a status code of `431` indicates the HTTP request made to *Authelia* had
headers exceeding the server [read_buffer_size](../../configuration/miscellaneous/server.md#read_buffer_size) parameter.

Usually the defaults are sufficient however some applications cause fairly large headers to be added to requests.

It's suggested you increase the [read_buffer_size](../../configuration/miscellaneous/server.md#read_buffer_size)
configuration option (by either doubling or quadrupling it) in order to alleviate this issue or use the reverse proxy to
remove the excessive headers which are causing this issue.

It's generally recommended the [write_buffer_size](../../configuration/miscellaneous/server.md#write_buffer_size) is
also increased.

## User Has Been Inactive Too Long

An error with the text `User john has been inactive for too long` where `john` is the username indicates the user did
not decide to utilize the remember me option, and their session has not been used for more time than is configured in
the session [inactivity](../../configuration/session/introduction.md#inactivity) configuration option.

This error can safely be ignored as it is meant to be informative. You can reduce this error from occurring by adjusting
the session [inactivity](../../configuration/session/introduction.md#inactivity) configuration option or by having users
select the remember me box.