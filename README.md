# Unhosted.py #

This is an HTTP server implementing the bare minimum required for the
[Unhosted.org](http://unhosted.org/) **remoteStorage** 
[`simple`](http://www.w3.org/community/rww/wiki/Read-write-web-00#simple)
API.

Hopefully this program will be useful for folks who want to study how
the remoteStorage protocol works or as a development tool for people
working on Unhosted apps.  As Unhosted matures, `Unhosted.py` will
hopefully also mature into a usable personal data-store for people who
want to store their Unhosted data on their own devices.


## Getting started ##

Quick-start:

   1. Install [pagekite.py](https://pagekite.net/downloads/)
   2. `pagekite.py --signup`
   3. Install [Unhosted.combined.py]()
   4. Run it in a console
   5. In another console, run: `pagekite.py 6789 rs-YOURNAME.pagekite.me`

You should now be able to use `*anything*@rs-YOURNAME.pagekite.me` as a
remoteStorage account.

Eventually this module will become one of the default plug-ins for
[`pagekite.py`](http://pagekite.org/), but for now it runs as a
stand-alone HTTP daemon.


## Play! ##

[5apps.com](http://5apps.com/) have written a [nice Unhosted tutorial
and test app](http://tutorial.unhosted.5apps.com/) which works just fine
with `Unhosted.py`.


## Hacking ##

The file `Unhosted.combined.py` is combination of `Unhosted.py` and the
`HttpdLite.py` module it depends on.  For hacking, you'll want to check
both out from github.


## Where is my data? ##

`Unhosted.py` stores data in `~/.Unhosted.py/`, in a relatively intuitive
directory structure:

    ~/.Unhosted.py/USER/CATEGORY/...

Each data folder will contain some regular files, as well as a file named
`_RS_METADATA.js`.  This meta-data file stores "real" names for all keys,
mime-types and may store other meta-data in the future.

The meta-data file may also store key values as well, if they are small
and do not really "look like a file".  This is an optimization to reduce
clutter and disk seeks when working with small keys: if the data is large
or looks like an independent file, it will be written as such to the
filesystem, although the name will probably be sanitized somewhat.

Note that changes to individual `_RS_METADATA.js` files may be overwritten
by `Unhosted.py` if it is running, as it caches their contents in RAM.
