import datetime
import hmac
import base64
import hashlib
import asyncio
import xmltodict

from functools import partial
from urllib.parse import quote

import aiohttp

from . import errors


amz_uriencode = partial(quote, safe='~')
amz_uriencode_slash = partial(quote, safe='~/')

_SIGNATURES = {}
SIGNATURE_V2 = 'v2'
SIGNATURE_V4 = 'v4'
SIG_V2_SUBRESOURCES = {
    'acl', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploadId',
    'uploads', 'versionId', 'versioning', 'versions', 'website'
    }


class Key(object):

    def __init__(self, *, key, last_modified, etag, size, storage_class):
        self.key = key
        self.last_modified = last_modified
        self.etag = etag
        self.size = int(size)
        self.storage_class = storage_class

    @classmethod
    def from_dict(Key, d):
        return Key(
            key=d['Key'], last_modified=datetime.datetime.strptime(d['LastModified'], '%Y-%m-%dT%H:%M:%S.000Z'),
            etag=d['ETag'], size=d['Size'], storage_class=d['StorageClass']
        )

    def __repr__(self):
        return '<Key {}:{}>'.format(self.key, self.size)


class Request(object):
    def __init__(self, verb, resource, query, headers, payload):
        self.verb = verb
        self.resource = amz_uriencode_slash(resource)
        self.params = query
        self.query_string = '&'.join(k + '=' + v if v is not None else k
            for k, v in sorted((amz_uriencode(k), amz_uriencode(v) if v is not None else None)
                               for k, v in query.items()))

        self.headers = headers
        self.payload = payload
        self.content_md5 = ''

    @property
    def url(self):
        hostHeader = self.headers['HOST']
        hostPort = hostHeader.split(':')
        proto = 'http'
        if (len(hostPort) == 2):
            if (hostPort[1] == '443'):
                proto = 'https'
        return '{1}://{0.headers[HOST]}{0.resource}?{0.query_string}' \
            .format(self, proto)


def _hmac(key, val):
    return hmac.new(key, val, hashlib.sha256).digest()


def _signkey(key, date, region, service):
    date_key = _hmac(("AWS4" + key).encode('ascii'),
                        date.encode('ascii'))
    date_region_key = _hmac(date_key, region.encode('ascii'))
    svc_key = _hmac(date_region_key, service.encode('ascii'))
    return _hmac(svc_key, b'aws4_request')


@partial(_SIGNATURES.setdefault, SIGNATURE_V4)
def sign_v4(req, *,
         aws_key, aws_secret, aws_service='s3', aws_region='us-east-1', **_):

    time = datetime.datetime.utcnow()
    date = time.strftime('%Y%m%d')
    timestr = time.strftime("%Y%m%dT%H%M%SZ")
    req.headers['x-amz-date'] = timestr
    if isinstance(req.payload, bytes):
        payloadhash = hashlib.sha256(req.payload).hexdigest()
    else:
        payloadhash = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'
    req.headers['x-amz-content-sha256'] = payloadhash

    signing_key = _signkey(aws_secret, date, aws_region, aws_service)

    headernames = ';'.join(k.lower() for k in sorted(req.headers))

    creq = (
        "{req.verb}\n"
        "{req.resource}\n"
        "{req.query_string}\n"
        "{headers}\n\n"
        "{headernames}\n"
        "{payloadhash}".format(
        req=req,
        headers='\n'.join(k.lower() + ':' + req.headers[k].strip()
            for k in sorted(req.headers)),
        headernames=headernames,
        payloadhash=payloadhash
        ))
    string_to_sign = (
        "AWS4-HMAC-SHA256\n{ts}\n"
        "{date}/{region}/{service}/aws4_request\n"
        "{reqhash}".format(
        ts=timestr,
        date=date,
        region=aws_region,
        service=aws_service,
        reqhash=hashlib.sha256(creq.encode('ascii')).hexdigest(),
        ))
    sig = hmac.new(signing_key, string_to_sign.encode('ascii'),
        hashlib.sha256).hexdigest()

    ahdr = ('AWS4-HMAC-SHA256 '
        'Credential={key}/{date}/{region}/{service}/aws4_request, '
        'SignedHeaders={headers}, Signature={sig}'.format(
        key=aws_key, date=date, region=aws_region, service=aws_service,
        headers=headernames,
        sig=sig,
        ))
    req.headers['Authorization'] = ahdr


def _hmac_old(key, val):
    return hmac.new(key, val, hashlib.sha1).digest()


@partial(_SIGNATURES.setdefault, SIGNATURE_V2)
def sign_v2(req, aws_key, aws_secret, aws_bucket, **_):
    time = datetime.datetime.utcnow()
    timestr = time.strftime("%Y%m%dT%H%M%SZ")
    req.headers['x-amz-date'] = timestr

    subresource = '&'.join(sorted(
        (k + '=' + v) if v else k
        for k, v in req.params.items()
        if k in SIG_V2_SUBRESOURCES))
    if subresource:
        subresource = '?' + subresource

    string_to_sign = (
        '{req.verb}\n'
        '{cmd5}\n'
        '{ctype}\n'
        '\n'  # date, we use x-amz-date
        '{headers}\n'
        '{resource}'
        ).format(
            req=req,
            cmd5=req.headers.get('CONTENT-MD5', '') or '',
            ctype=req.headers.get('CONTENT-TYPE', '') or '',
            headers='\n'.join(k.lower() + ':' + req.headers[k].strip()
                for k in sorted(req.headers)
                if k.lower().startswith('x-amz-')),
            resource='/' + aws_bucket + req.resource + subresource)
    sig = base64.b64encode(
        _hmac_old(aws_secret.encode('ascii'), string_to_sign.encode('ascii'))
        ).decode('ascii')
    ahdr = 'AWS {key}:{sig}'.format(key=aws_key, sig=sig)
    req.headers['Authorization'] = ahdr


class ObjectChunk(object):
    def __init__(self, bucket, key, firstByte, lastByte, versionId=None):
        if (isinstance(bucket, Bucket)):
            bucket = bucket._name
        self.bucket = bucket
        self.key = key
        self.firstByte = firstByte
        self.lastByte = lastByte
        self.versionId = versionId



class MultipartUpload(object):

    def __init__(self, bucket, key, upload_id):
        self.bucket = bucket
        self.key = key
        self.upload_id = upload_id
        self.parts = dict()  # num -> etag
        self._done = False
        self._uri = '/' + self.key + '?uploadId=' + self.upload_id

    @asyncio.coroutine
    def add_chunk(self, data):
        assert isinstance(data, (bytes, memoryview, bytearray, ObjectChunk)), data

        # figure out how to check chunk size, all but last one
        # assert len(data) > 5 << 30, "Chunk must be at least 5Mb"

        if self._done:
            raise RuntimeError("Can't add_chunk after commit or close")
        
        partNumber = len(self.parts) + 1
        self.parts[partNumber] = None

        headers = {
            'HOST': self.bucket._host,
            # next one aiohttp adds for us anyway, so we must put it here
            # so it's added into signature
            'CONTENT-TYPE': 'application/octed-stream',
        }

        isCopy = False
        if (isinstance(data, ObjectChunk)):
            objChunk = data
            data = b''
            srcPath = "/{0}/{1}".format(objChunk.bucket, amz_uriencode(objChunk.key))
            if (objChunk.versionId is not None):
                srcPath = srcPath + "?versionId={0}".format(objChunk.versionId)
            headers['x-amz-copy-source'] = srcPath
            headers['x-amz-copy-source-range'] = "bytes={0}-{1}".format(objChunk.firstByte, objChunk.lastByte)
            isCopy = True
        else:
            headers['CONTENT-LENGTH'] = str(len(data))

        result = yield from self.bucket._request(Request("PUT",
            '/' + self.key, {
                'uploadId': self.upload_id,
                'partNumber': str(partNumber),
            }, headers=headers, payload=data))
        try:
            xml = yield from result.read()
            if result.status != 200:
                raise errors.AWSException.from_bytes(result.status, xml, self.key + ":" + str(partNumber))
            if not isCopy:
                etag = result.headers['ETAG']   # per AWS docs get the etag from the headers
            else:
                # Per AWS docs if copy case need to get the etag from the XML response
                xml = xmltodict.parse(xml)["CopyPartResult"]
                etag = xml["ETag"]
                if etag.startswith("\""): etag = etag[1:-1]
        finally:
            yield from result.wait_for_close()
            
        self.parts[partNumber] = etag
        
    @asyncio.coroutine
    def commit(self):
        if self._done:
            raise RuntimeError("Can't commit twice or after close")
        self._done = True

        self.parts = [{'PartNumber': n, 'ETag': etag} for n, etag in self.parts.items()]
        self.parts = sorted(self.parts, key=lambda x: x['PartNumber'])
        self.xml = {"CompleteMultipartUpload": {'Part': self.parts}}
        data = xmltodict.unparse(self.xml, full_document=False).encode('utf8')

        result = yield from self.bucket._request(Request("POST",
            '/' + self.key, {
                'uploadId': self.upload_id,
            }, headers={
                'CONTENT-LENGTH': str(len(data)),
                'HOST': self.bucket._host,
                'CONTENT-TYPE': 'application/xml',
            }, payload=data))
        try:
            xml = yield from result.read()
            if result.status != 200:
                raise errors.AWSException.from_bytes(result.status, xml, self.key)
            xml = xmltodict.parse(xml)['CompleteMultipartUploadResult']
            return xml
        finally:
            yield from result.wait_for_close()

    @asyncio.coroutine
    def close(self):
        if self._done:
            return
        self._done = True
        result = yield from self.bucket._request(Request("DELETE",
            '/' + self.key, {
                'uploadId': self.upload_id,
            }, headers={'HOST': self.bucket._host}, payload=b''))
        try:
            xml = yield from result.read()
            if result.status != 204:
                raise errors.AWSException.from_bytes(result.status, xml, self.key)
        finally:
            yield from result.wait_for_close()

@asyncio.coroutine
def getLocation(name, *, port=80, aws_key, aws_secret, connector=None):
    b = Bucket(name=name, port=port, aws_key=aws_key, aws_secret=aws_secret, connector=connector, signature=SIGNATURE_V2)
    request = Request("GET", "/", {'location' : None}, {'HOST': b._host}, b'')
    # whack the params field because the constructor set it wrong.
    request.params = {'location' : None}
    # whack the query_string field because the constructor set it wrong.
    request.query_string = "location"
    result = yield from b._request(request)
    try:
        data = yield from result.read()
        if result.status != 200:
            raise errors.AWSException.from_bytes(result.status, data, b._name)

        xml = xmltodict.parse(xml)['LocationConstraint']
        region = xml
        if (region is None) or (len(region) == 0):
            return 'us-east-1'
        return region
    finally:
        yield from result.wait_for_close()

class Bucket(object):

    def __init__(self, name, *,
                 port=80,
                 aws_key, aws_secret,
                 aws_region='us-east-1',
                 aws_endpoint='s3.amazonaws.com',
                 signature=SIGNATURE_V4,
                 connector=None,
                 cred_resolver=None):  # method must return the tuple: (aws_key, aws_secret)
        self._name = name
        self._connector = None
        self._aws_sign_data = {
            'aws_key': aws_key,
            'aws_secret': aws_secret,
            'aws_region': aws_region,
            'aws_service': 's3',
            'aws_bucket': name,
        }

        self._host = self._name + '.' + aws_endpoint
        self._cred_resolver = cred_resolver

        if port != 80:
            self._host = self._host + ':' + str(port)

        self._signature = signature
        self._session = aiohttp.ClientSession(connector=connector)

    def _update_creds(self):
        if not self._cred_resolver: return

        self._aws_sign_data["aws_key"], self._aws_sign_data["aws_secret"] = self._cred_resolver()

    @asyncio.coroutine
    def exists(self, prefix=''):
        result = yield from self._request(Request(
            "GET",
            "/",
            {'prefix': prefix,
             'separator': '/',
             'max-keys': '1'},
            {'HOST': self._host},
            b''))
        data = yield from result.read()
        if result.status != 200:
            raise errors.AWSException.from_bytes(result.status, data, self._name)
        x = xmltodict.parse(data)['ListBucketResult']
        return any(map(Key.from_dict, x["Contents"]))

    @asyncio.coroutine
    def list(self, prefix='', max_keys=1000):
        result = yield from self._request(Request(
            "GET",
            "/",
            {'prefix': prefix,
             'max-keys': str(max_keys)},
            {'HOST': self._host},
            b'',
            ))
        data = (yield from result.read())
        if result.status != 200:
            raise errors.AWSException.from_bytes(result.status, data, self._name)

        x = xmltodict.parse(data)['ListBucketResult']

        if 'IsTruncated' != 'false':
            raise AssertionError("File list is truncated, use bigger max_keys")

        return list(map(Key.from_dict, x["Contents"]))

    def list_by_chunks(self, prefix='', max_keys=1000):
        final = False
        marker = ''

        @asyncio.coroutine
        def read_next():
            nonlocal final, marker

            result = yield from self._request(Request(
                "GET",
                "/",
                {'prefix': prefix,
                 'max-keys': str(max_keys),
                 'marker': marker},
                {'HOST': self._host},
                b'',
            ))

            try:
                data = yield from result.read()
                if result.status != 200:
                    raise errors.AWSException.from_bytes(result.status, data, self._name)
                x = xmltodict.parse(data)['ListBucketResult']

                result = list(map(Key.from_dict, x['Contents'])) if "Contents" in x else []

                if x['IsTruncated'] == 'false' or len(result) == 0:
                    final = True
                else:
                    if 'NextMarker' not in x:  # amazon, really?
                        marker = result[-1].key
                    else:
                        marker = x['NextMarker']

                return result
            finally:
                yield from result.wait_for_close()

        while not final:
            yield read_next()

    @asyncio.coroutine
    def head(self, key, versionId=None):
        if isinstance(key, Key):
            key = key.key

        params = {} if versionId is None else {'versionId' : versionId}
        result = yield from self._request(Request(
            "HEAD", '/' + key, params, {'HOST': self._host}, b''))

        try:
            if result.status != 200:
                xml = yield from result.read()
                raise errors.AWSException.from_bytes(result.status, xml, key)

            obj = {'Metadata': dict()}
            for h, v in result.headers.items():
                if not h.startswith('X-AMZ-META-'): continue
                obj['Metadata'][h[11:].lower()] = v  # boto3 returns keys in lowercase
        
            return obj
        finally:
            yield from result.wait_for_close()


    @asyncio.coroutine
    def download(self, key, versionId=None):
        if isinstance(key, Key):
            key = key.key
        params = {} if versionId is None else {'versionId' : versionId}
        result = yield from self._request(Request(
            "GET", '/' + key, params, {'HOST': self._host}, b''))

        try:
            if result.status != 200:
                raise errors.AWSException.from_bytes(
                    result.status, (yield from result.read()), key)
            return result
        finally:
            yield from result.wait_for_close()

    @asyncio.coroutine
    def upload_file(self, key, file_path):
        data = open(file_path, 'rb').read()
        yield from self.upload(key, data, len(data))

    @asyncio.coroutine
    def upload(self, key, data,
            content_length=None,
            content_type='application/octed-stream'):
        """Upload file to S3

        The `data` might be a generator or stream.

        the `content_length` is unchecked so it's responsibility of user to
        ensure that it matches data.

        Note: Riak CS doesn't allow to upload files without content_length.
        """
        if isinstance(key, Key):
            key = key.key
        if isinstance(data, str):
            data = data.encode('utf-8')

        headers = {
            'HOST': self._host,
            'CONTENT-TYPE': content_type,
            }

        if content_length is not None:
            headers['CONTENT-LENGTH'] = str(content_length)

        result = yield from self._request(Request("PUT", '/' + key, {},
            headers=headers, payload=data))

        try:
            if result.status != 200:
                xml = yield from result.read()
                raise errors.AWSException.from_bytes(result.status, xml, key)
            return result
        finally:
            yield from result.wait_for_close()

    @asyncio.coroutine
    def delete(self, key):
        if isinstance(key, Key):
            key = key.key
        result = yield from self._request(Request("DELETE", '/' + key, {},
            {'HOST': self._host}, b''))
        try:
            if result.status != 204:
                xml = yield from result.read()
                raise errors.AWSException.from_bytes(result.status, xml, key)
            return result
        finally:
            yield from result.wait_for_close()

    @asyncio.coroutine
    def copy(self, copy_source, key):
        if isinstance(key, Key):
            key = key.key

        result = yield from self._request(Request("PUT", '/' + key, {},
            {
                'HOST': self._host,
                'x-amz-copy-source': copy_source,
             }, b'',
        ))
        try:
            xml = yield from result.read()
            if result.status != 200:
                raise errors.AWSException.from_bytes(result.status, xml, key)
            return xmltodict.parse(xml)["CopyObjectResult"]
        finally:
            yield from result.wait_for_close()

    @asyncio.coroutine
    def get(self, key):
        if isinstance(key, Key):
            key = key.key
        result = yield from self._request(Request(
            "GET", '/' + key, {}, {'HOST': self._host}, b''))

        try:
            if result.status != 200:
                raise errors.AWSException.from_bytes(
                    result.status, (yield from result.read()), key)
            data = yield from result.read()
            return data
        finally:
            yield from result.wait_for_close()

    @asyncio.coroutine
    def _request(self, req):
        self._update_creds()

        _SIGNATURES[self._signature](req, **self._aws_sign_data)
        if isinstance(req.payload, bytes):
            req.headers['CONTENT-LENGTH'] = str(len(req.payload))
        return (yield from self._session.request(req.verb, req.url,
            chunked='CONTENT-LENGTH' not in req.headers,
            headers=req.headers,
            data=req.payload))

    @asyncio.coroutine
    def upload_multipart(self, key,
            content_type='application/octed-stream',
            MultipartUpload=MultipartUpload,
            metadata={}):
        """Upload file to S3 by uploading multiple chunks"""

        if isinstance(key, Key):
            key = key.key

        q_obj = {
            'HOST': self._host,
            'CONTENT-TYPE': content_type,
        }

        for n, v in metadata.items():
            q_obj["x-amz-meta-" + n] = v

        result = yield from self._request(Request("POST", '/' + key, {'uploads': ''}, q_obj, payload=b''))

        try:
            if result.status != 200:
                xml = yield from result.read()
                raise errors.AWSException.from_bytes(result.status, xml, key)
            xml = yield from result.read()
            xml = xmltodict.parse(xml)['InitiateMultipartUploadResult']

            upload_id = xml['UploadId']

            assert upload_id
            return MultipartUpload(self, key, upload_id)
        finally:
            yield from result.wait_for_close()

    @asyncio.coroutine
    def abort_multipart_upload(self, key, upload_id):
        if isinstance(key, Key):
            key = key.key

        result = yield from self._request(Request(
            "DELETE", '/' + key + "uploadId=" + upload_id, {}, {'HOST': self._host}, b''))

        try:
            if result.status != 204:
                xml = yield from result.read()
                raise errors.AWSException.from_bytes(result.status, xml, key)
        finally:
            yield from result.wait_for_close()

    def list_multipart_uploads_by_chunks(self, prefix='', max_uploads=1000):
        final = False
        key_marker = ''
        upload_id_marker = ''

        @asyncio.coroutine
        def read_next():
            nonlocal final, key_marker, upload_id_marker

            query = {'uploads': '', 'max-uploads': str(max_uploads)}
            if len(prefix):
                query['prefix'] = prefix

            if len(key_marker):
                query['key-marker'] = key_marker
                query['upload-id-market'] = upload_id_marker

            result = yield from self._request(Request(
                "GET", "/", query,
                {'HOST': self._host},
                b''
            ))

            try:
                data = yield from result.read()
                if result.status != 200:
                    raise errors.AWSException.from_bytes(result.status, data)

                x = xmltodict.parse(data)['ListMultipartUploadsResult']

                if x['IsTruncated'] == 'false' or len(x['Upload']) == 0:
                    final = True
                else:
                    key_marker = x['NextKeyMarker']
                    upload_id_marker = x['NextUploadIdMarker']
            finally:
                yield from result.wait_for_close()

            return x

        while not final:
            yield read_next()
