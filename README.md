# NewNode

## Integration status

[![Stories in Ready](https://badge.waffle.io/clostra/dcdn.svg?label=ready&title=Ready)](http://waffle.io/clostra/dcdn)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/fbeb689ec190470a90645fb016cbcfb7)](https://www.codacy.com/app/shalunov/dcdn)
[ ![Download](https://api.bintray.com/packages/clostra/newnode/newnode/images/download.svg) ](https://bintray.com/clostra/newnode/newnode/_latestVersion)

## How to contribute

1. Prepare your dev environment
2. Deal with an issue
3. Go into development mode

## How to prepare your dev environment

1. Fork the repo
2. `git clone --recursive git@github.com:`〈*your username*〉`/newnode.git` (NB: **--recursive**)
3. `./build.sh && ./test.sh`
4. When your build works and tests pass, you're ready to contribute

## How to deal with an issue

1. Get an issue assigned by @shalunov
2. Work on the issue in your forked repo
3. If you like feature branches, you can do that
4. When you're satisfied with your changes, send a pull request and **tag the issue the end of the title**
5. Wait for CI checks to complete on the pull request; if they fail, you'll need to revise
6. If code review is requested, wait for the reviewer to provide one
7. If the reviewer requests revisions, discuss, address, and probably revise
8. When your pull request is merged, double-check the CI status on the merge commit before celebrating

## How to go into development mode

In development mode, you deal with issues one after another, and maintain enough pipeline so you're not just waiting for reviews, merges, and assignments. This normally means having a backup issue assigned; this way, after you're done with the issue you're working on and send a pull request, you can work on the other issue. Feature branches make it more convenient to work on multiple issues like that.

You may be asked to review a merge request. Please try to be timely with your review. Be kind, but firm in your review: we want things to be the best we can make them, but we are also a community. When providing the review, always make it very clear whether you think the pull request should be merged—start your review with  or . If you think it's good to go, you may still provide optional comments, but it's not necessary. Obviously a request for revision or outright rejection needs to be explained.

## Coding style

1. Follow existing coding style, including `.clang-format`
2. Name things after what they are
3. The smallest changeset that addresses the issue is best
4. Keep related things close
