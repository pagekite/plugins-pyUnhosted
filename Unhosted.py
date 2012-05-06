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
import json
import os
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



class RequestHandler(HttpdLite.RequestHandler):
  def do_OPTIONS(self):
    return self.do_GET(command='OPTIONS')


class Unhosted:
  def __init__(self, db_path):
    self.db_path = db_path
    self.db_metadata = {}
    self.db_password = '%x-%x' % (os.getpid(), random.randint(0, 0xFFFF))
    self.listen_on = ('localhost', 6789)

  def stop(self):
    pass

  CORS_HEADERS = [
    ('Access-Control-Allow-Origin', '*'),
    ('Access-Control-Allow-Methods', 'GET, PUT, DELETE'),
    ('Access-Control-Allow-Headers', 'content-length, authorization')
  ]
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
    cachectrl = 'no-cache'
    data = None

    # Shared values for rendering templates
    host = req.header('Host', 'unknown')
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
                            code=code, mimetype=mime_type,
                            header_list=headers, cachectrl=cachectrl)

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
      redirect = None
      if 'deny' in posted:
        redirect = '%s#error=invalid_client' % redirect_uri
      elif posted.get('password', [''])[0] == self.db_password:
        parts = []
        print '%s' % posted
        for i in range(0, len(scope)):
          if ('r_%s' % i) in posted:
            parts.append('r_%s' % scope[i])
          if ('w_%s' % i) in posted:
            parts.append('w_%s' % scope[i])
        if parts:
          parts.extend([subject])
          parts.append(sha1sig([self.db_password]+parts))
          token = ','.join(parts)
          redirect = ('%s#access_token=%s&token_type=bearer'
                      ) % (redirect_uri, token)
        else:
          redirect = '%s#error=invalid_request' % redirect_uri

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

  def checkAuth(self, req, user):
    try:
      how, parts = req.header('Authorization', ' ').split()
      if how.lower() != 'bearer': raise ValueError(how)
      parts = parts.split(',')
      sig = parts.pop(-1)
      if sig != sha1sig([self.db_password]+parts): raise ValueError('sig')
      if parts.pop(-1) != user: raise ValueError(user)
      print 'Creds: %s' % parts
      return parts
    except (ValueError, KeyError), e:
      return ['r_public', 'error_%s' % e]

  def mkdir(self, path):
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname): self.mkdir(dirname)
    os.mkdir(path)

  def getMetadata(self, dirname):
    if dirname in self.db_metadata:
      return self.db_metadata[dirname]
    try:
      md = json.load(open(os.path.join(dirname, '_RS_METADATA.js'), 'rb'))
      self.db_metadata[dirname] = md
    except (OSError, IOError):
      md = {}
    return md

  def setMetadata(self, dirname, key, value):
    md = self.getMetadata(dirname)
    md[key] = value
    self.saveMetadata(dirname, md)

  def delMetadata(self, dirname, key, value):
    md = self.getMetadata(dirname)
    if key in md:
      del md[key]
      self.saveMetadata(dirname, md)

  def saveMetadata(self, dirname, md):
    # FIXME: Use zlib to make this smaller?
    # FIXME: Just mark dirty, move the actual writes to another thread.
    json.dump(md, open(os.path.join(dirname, '_RS_METADATA.js'), 'wb'), indent=2)

  def getFile(self, filename, authenticated):
    dirname, basename = os.path.split(filename)
    metadata = self.getMetadata(dirname).get(basename, None)
    if not metadata:
      if authenticated and os.path.isdir(filename):
        return '{}', 'application/json', 200 # FIXME: Directory listing?
      else:
        return '<h1>Not Found</h1>\n', 'text/html', 404

    if authenticated or 'r' in metadata.get('public', ''):
      mime_type = metadata.get('mime-type', 'text/plain')
      data = metadata.get('data', '')
      if 'file-name' in metadata:
        data = ''.join(open(os.path.join(dirname, metadata['file-name'], 'rb')
                            ).readlines())
    else:
      return '<h1>Unauthorized</h1>\n', 'text/html', 401

    return data, mime_type, 200

  def putFile(self, filename, data, mime_type, authenticated):
    dirname, basename = os.path.split(filename)
    if authenticated:
      if not os.path.exists(dirname): self.mkdir(dirname)
    else:
      metadata = self.getMetadata(dirname).get(basename, None)
      if 'w' not in metadata.get('public', ''):
        return '<h1>Unauthorized</h1>\n', 'text/html', 401

    if data == '' and not mime_type:
      os.mkdir(filename)
    else:
      metadata = {
        'mime-type': mime_type or 'application/octet-stream'
      }
      # FIXME: Magic number alert!
      if len(data) > 32000:
        fn = metadata['file-name'] = urllib.quote(basename)
        fd = open(os.path.join(dirname, fn), 'wb')
        fd.write(data)
        fd.close()
      else:
        metadata['data'] = data
      self.setMetadata(dirname, basename, metadata)

    # FIXME: Return codes?
    return '', 'text/plain', 200

  def delFile(self, filename, authenticated):
    dirname, basename = os.path.split(filename)
    metadata = self.getMetadata(dirname).get(basename, None)
    if not metadata or not authenticated:
      return '<h1>Not Found</h1>\n', 'text/html', 404

    if 'file-name' in metadata:
      os.remove(os.path.join(dirname, metadata['file-name']))
    self.delMetadata(dirname, basename)

    return '', 'text/html', 200


  def handleStorage(self, req, path, page, qs, posted):
    headers = self.CORS_HEADERS[:]
    cachectrl = 'no-cache'

    # Clean up our path a bit...
    if '..' in path: raise ValueError('Evil path: %s' % path)

    # Calculate our filename
    filename = os.path.normpath('/'.join([self.db_path, path]))

    # Strip user and category off the path
    user, category, path = path.split('/', 2)
    creds = self.checkAuth(req, user)

    if req.command == 'OPTIONS':
      data, mime_type, code = '', 'text/html', 200

    elif req.command == 'GET':
      authenticated = ('r_%s' % category) in creds
      data, mime_type, code = self.getFile(filename, authenticated)

    elif req.command == 'PUT':
      authenticated = ('w_%s' % category) in creds
      data, mime_type, code = self.putFile(filename, posted['PUT'],
                                           req.header('Content-Type'),
                                           authenticated)

    elif req.command == 'DELETE':
      authenticated = ('w_%s' % category) in creds
      data, mime_type, code = self.delFile(filename, authenticated)

    else:
      data, mime_type, code = 'Unimplemented', 'text/html', 500

    return req.sendResponse(data, code=code, mimetype=mime_type,
                            header_list=headers, cachectrl=cachectrl)


if __name__ == "__main__":
  try:
    db_path = os.path.expanduser('~/.Unhosted.py')
    unhosted = Unhosted(db_path)
  except (IndexError, ValueError, OSError, IOError):
    print 'Usage: %s' % sys.argv[0]
    print
    print 'The file will create an database in: %s' % db_file
    print
    sys.exit(1)
  try:
    try:
      HttpdLite.Server(unhosted.listen_on, unhosted,
                       handler=RequestHandler).serve_forever()
    except KeyboardInterrupt:
      unhosted.stop()
  except:
    unhosted.stop()
    raise

