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
import hashlib
import os
import oauth
import random
import time
import urllib

import HttpdLite


html_escape_table = {
  "&": "&amp;",
  '"': "&quot;",
  "'": "&apos;",
  ">": "&gt;",
  "<": "&lt;",
}
def html_escape(text):
  """Produce entities within text."""
  return "".join(html_escape_table.get(c,c) for c in text)

def sha1sig(parts):
  h = hashlib.sha1()
  h.update(('-'.join(parts)).encode('utf-8'))
  return h.digest().encode('base64').replace('+', '^').replace('=', '').strip()


class Unhosted:
  def __init__(self, db_path):
    self.db_path = db_path
    self.db_password = '%x-%x' % (os.getpid(), random.randint(0, 0xFFFF))
    self.listen_on = ('localhost', 6789)

  def stop(self):
    pass

  CORS_HEADERS = [('Access-Control-Allow-Origin', '*')]
  HOST_META = """<?xml version='1.0' encoding='UTF-8'?>
<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>
  <Link rel='lrdd' type='application/xrd+xml'
                   template='%(proto)s://%(host)s/webfinger?uri={uri}'/>
</XRD>
"""
  WEBFINGER = """<?xml version='1.0' encoding='UTF-8'?>
<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>
  <Link rel='remoteStorage'
        api='simple'
        auth='%(unhosted_url)s/oauth?user=%(q_user)s'
        template='%(unhosted_url)s/storage/%(q_user)s/{category}/' />
</XRD>
"""

  def handleHttpRequest(self, req, scheme, netloc, path,
                              params, query, frag,
                              qs, posted, cookies, user=None):
    if path.startswith('/'): path = path[1:]
    path_url = path
    path = urllib.unquote(path).decode('utf-8')

    # Defaults, may be overridden by individual response pages
    code = 200
    headers = self.CORS_HEADERS[:]
    cachectrl = 'max-age=600, private'
    data = None

    # Shared values for rendering templates
    host = req.headers.get('HOST', req.headers.get('host', 'unknown'))
    page = {
      'proto': 'https', # FIXME
      'host': host,
    }
    page['unhosted_url'] = '%(proto)s://%(host)s' % page
    # host meta
    if req.command == 'GET' and path == '.well-known/host-meta':
      mime_type = 'application/xrd+xml'
      template = self.HOST_META

    elif req.command == 'GET' and path == 'webfinger':
      # FIXME: Does user really exist?
      page['subject'] = subject = qs['uri'][0]
      page['user'] = subject.split(':', 1)[-1].replace('@'+host, '')
      mime_type = 'application/xrd+xml'
      template = self.WEBFINGER.replace('\n', '\r\n')

    elif path == 'oauth':
      return self.handleOAuth(req, page, qs, posted)

    elif path.startswith('storage/'):
      return self.handleStorage(req, path[8:], page, qs, posted)

    else:
      code = 404
      mime_type = 'text/html'
      template = '<h1>404 Not found</h1>\n'

    if not data:
      for key in page.keys():
        page['q_%s' % key] = urllib.quote(page[key])
    return req.sendResponse(data or ((template % page).encode('utf-8')),
                            code=code,
                            mimetype=mime_type,
                            header_list=headers,
                            cachectrl=cachectrl)

  OAUTH_GRANT = """<!DOCTYPE html>
<html><head>
  <title>OAuth: Grant access?</title>
</head><body><form method='POST'>
  <h1>Grant access?</h1>
  <p>The app at <b>%(h_client_id)s</b> would like to read and write
     data for <b>%(h_user)s</b>.  Please log in and tick all permissions
     you'd like to grant to this app.  Note that some applications may fail
     if not all are granted.</p>
  <table><tr>
    <th>Read</th><th>Write</th><th>Category</th>%(rw_scopes)s
  </tr></table>
  <p>Password: <input type='password' name='password' value=''>
     <i>* check the console</i></p>
  <p><input type=submit value='Allow'>
     <input type=submit name='deny' value='Deny'></p>
</form></body></html>
"""
  OAUTH_SCOPE = """
  </tr><tr>
    <td><input type='checkbox' name='r_%(cat)s' checked></td>
    <td><input type='checkbox' name='w_%(cat)s' checked></td>
    <td><b>%(scope)s</b></td>"""

  def handleOAuth(self, req, page, qs, posted):
    page['user'] = subject = qs['user'][0]
    page['client_id'] = client_id = qs['client_id'][0]
    redirect_uri = qs['redirect_uri'][0]
    response_type = qs['response_type'][0]
    state = qs.get('state', [None])[0]

    scope = qs.get('scope', [None])[0]
    scope = scope and scope.split(',') or []

    if posted:
      redirect = '%s#error=invalid_request' % redirect_uri
      if 'deny' in posted:
        redirect = '%s#error=invalid_client' % redirect_uri
      elif posted.get('password', [''])[0] == self.db_password:
        parts = []
        for i in range(0, len(scope)):
          if 'r_%s' % i in posted:
            parts.append('r_%s' % scope[i])
          if 'w_%s' % i in posted:
            parts.append('w_%s' % scope[i])
        if parts:
          parts.extend([subject])
          parts.append(sha1sig(parts))
          token = ','.join(parts)
          redirect = ('%s#access_token=%s&token_type=bearer'
                      ) % (redirect_uri, token)

      if redirect:
        req.sendResponse(('<h1>Redirecting to <a href="%s">%s</a></h1>'
                          ) % (redirect, redirect),
                         code=302,
                         header_list=[('Location', redirect)])


    scope_html = []
    for cat in range(0, len(scope)):
      scope_html.append(self.OAUTH_SCOPE % {'cat': cat,
                                            'scope': html_escape(scope[cat])})
    page['rw_scopes'] = ''.join(scope_html)

    print
    print '*** YOUR TEMPORARY PASSWORD: %s' % self.db_password
    print

    for key in page.keys():
      page['h_%s' % key] = html_escape(page[key])
    return req.sendResponse((self.OAUTH_GRANT % page).encode('utf-8'),
                            code=500)

  def handleStorage(self, req, path, page, qs, posted):
    code = 500
    headers = self.CORS_HEADERS[:]
    cachectrl = 'max-age=600, private'

    data = 'Unimplemented'
    mime_type = 'text/html'

    return req.sendResponse(data,
                            code=code,
                            mimetype=mime_type,
                            header_list=headers,
                            cachectrl=cachectrl)


if __name__ == "__main__":
  try:
    db_path = os.path.expanduser('~/.Unhosted.py/')
    unhosted = Unhosted(db_path)
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

