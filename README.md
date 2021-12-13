# tcptrace for macOS

This project takes the most recent version of tcptrace by Shawn Ostermann
(version 6.6.7 from May 25, 2001!), and ports it forward so tcptrace may be
installed on macOS. The original source of tcptrace was downloaded from
[tcptrace.org](tcptrace.org) via
[archive.org](https://web.archive.org/web/20200806203343/http://www.tcptrace.org/download.shtml).
Only the most minimal changes required build, install, and uninstall tcptrace on macOS
and Ubuntu have been made. No substantial features have been added, nor are any features
planned.

Since tcptrace.org has a history of going offline, and there is no official VCS
repository, I decided to import as many versions of tcptrace into git as
possible. Some versions are missing from the commit history since archive.org
did not have the tarball.

tcptrace's README is [README](README).


## Installation
Surprisingly, no changes were necessary to get tcptrace to build on a recent
version of macOS, but changes were made to fix `make install`. There are a lot
of compiler warnings though.

A small change was neccessary to fix the Ubuntu build. Thankfully, the Debian
maintainers already fixed this
([`f36b1567a5`](https://github.com/msagarpatel/tcptrace/commit/f36b1567a5691d4c32489ab8493d8d4faaad3935)).

Simply run
```shell
./configure
make
make install
```
to build and install tcptrace. Then, run tcptrace like so
```shell
tcptrace /path/to/tcptrace/file
```
The following man page is also installed: `tcptrace(1)`.


### Build Quirks
Interestingly, three source files in flex_bison/ are modified during the build
process. This isn't a best practice, but it works. I am leaving this unmodified
to preserve tcptrace as-is.


## Large Files
All files in the following two directories are stored using
[Git LFS](https://git-lfs.github.com):

- [`cygwin-libs`](cygwin-includes): contains libraries for compiling on Cygwin.
- [`input`](input): contains sample files to use with tcptrace.

So, these files are not required for compiling on macOS, but they're available
if you want to see them. If you don't want to install LFS, I've configured the
ZIP file that can be downloaded from GitHub to include the LFS files. You can
also browse those directories on GitHub, and download individual LFS files.


## Support
This project has been tested on macOS Big Sur 11.4 on both x86 and Apple
Silicon. I'd love to hear if you successfully build and run this project on
another system. Please open an issue to let me know.


## Uninstallation
If tcptrace was installed with `make install`, then it may be uninstalled using
```shell
make uninstall
```


## Contributing
Pull requests that add support or documentation for more operating systems are
welcome.
