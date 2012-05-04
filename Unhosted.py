#!/usr/bin/python
#
# Unhosted.py, Copyright 2012, Bjarni R. Einarsson <http://bre.klaki.net/>
#
# This is an "instant" personal Unhosted.org remoteStorage server.
#
################################################################################
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the  GNU  Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,  but  WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see: <http://www.gnu.org/licenses/>
#
################################################################################
#
import os
import oauth
import random
import sqlite3
import urllib

import HttpdLite


class Unhosted:
  def __init__(self, db_path):
    self.db = sqlite3.connect(db_path).cursor()
    self.listen_on = ('localhost', 6789)

  def stop(self):
    self.db.close()

  CORS_HEADERS = [('Access-Control-Allow-Origin', '*')]
  HOST_META = """\
<?xml version="1.0" encoding="UTF-8"?>
<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <Link rel="lrdd" type="application/xrd+xml"
                   template="%(proto)s://%(host)s/webfinger/?uri={uri}"/>
</XRD>
"""

  def handleHttpRequest(self, req, scheme, netloc, path,
                              params, query, frag,
                              qs, posted, cookies, user=None):
    if path.endswith('/'): path = path[:-1]
    if path.startswith('/'): path = path[1:]
    path_url = path
    path = urllib.unquote(path).decode('utf-8')

    headers = self.CORS_HEADERS[:]
    page = {
      'proto': 'http', # FIXME
      'host': req.headers.get('HOST', req.headers.get('host', 'unknown')),
    }

    if path == '.well-known/host-meta':
      mime_type = 'application/xrd+xml'
      data = self.HOST_META % page

    elif path == 'webfinger':
      mime_type = 'application/xrd+xml'
      data = self.WEBFINGER % page

    else:
      mime_type = 'text/plain'
      data = 'Hello world'

    return req.sendResponse(data.encode('utf-8'),
                            mimetype=mime_type,
                            header_list=headers,
                            cachectrl='max-age=600, private')

    raise Exception('Unimplemented')


if __name__ == "__main__":
  try:
    db_file = os.path.expanduser('~/.Unhosted.py.sq3')
    unhosted = Unhosted(db_file)
  except (IndexError, ValueError, OSError, IOError):
    print 'Usage: %s' % sys.argv[0]
    print
    print 'The file will create an database in: %s' % db_file
    print
    sys.exit(1)
  try:
    try:
      import HttpdLite
      HttpdLite.Server(unhosted.listen_on, unhosted).serve_forever()
    except KeyboardInterrupt:
      unhosted.stop()
  except:
    unhosted.stop()
    raise

