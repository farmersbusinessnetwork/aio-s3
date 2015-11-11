import datetime
import hmac
import logging
import hashlib
import asyncio
import xmltodict
import collections
import time

from functools import partial
from urllib.parse import quote

import aiohttp

from . import errors


amz_uriencode = partial(quote, safe='~')
amz_uriencode_slash = partial(quote, safe='~/')


def _safe_list(obj):
    if isinstance(obj, collections.OrderedDict):
        return [obj]
    return obj


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


def _hmac(key, val):
    return hmac.new(key, val, hashlib.sha256).digest()


def _signkey(key, date, region, service):
    date_key = _hmac(("AWS4" + key).encode('ascii'),
                        date.encode('ascii'))
    date_region_key = _hmac(date_key, region.encode('ascii'))
    svc_key = _hmac(date_region_key, service.encode('ascii'))
    return _hmac(svc_key, b'aws4_request')


def sign_v4(verb, resource, query_string, headers, payload, aws_key, aws_secret, aws_service='s3', aws_region='us-east-1', **_):
    time = datetime.datetime.utcnow()
    date = time.strftime('%Y%m%d')
    timestr = time.strftime("%Y%m%dT%H%M%SZ")
    headers['x-amz-date'] = timestr

    if isinstance(payload, bytes):
        payloadhash = hashlib.sha256(payload).hexdigest()
    else:
        payloadhash = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'

    headers['x-amz-content-sha256'] = payloadhash

    signing_key = _signkey(aws_secret, date, aws_region, aws_service)
    header_names = ';'.join(k.lower() for k in sorted(headers))
    header_str = '\n'.join(k.lower() + ':' + headers[k].strip() for k in sorted(headers))

    creq = (
        "{verb}\n"
        "{resource}\n"
        "{query_string}\n"
        "{header_str}\n\n"
        "{header_names}\n"
        "{payloadhash}".format(
            verb=verb,
            resource=resource,
            query_string=query_string,
            header_str=header_str,
            header_names=header_names,
            payloadhash=payloadhash,
        )
    )

    string_to_sign = (
        "AWS4-HMAC-SHA256\n{ts}\n"
        "{date}/{region}/{service}/aws4_request\n"
        "{reqhash}".format(
            ts=timestr,
            date=date,
            region=aws_region,
            service=aws_service,
            reqhash=hashlib.sha256(creq.encode('ascii')).hexdigest(),
        )
    )

    sig = hmac.new(signing_key, string_to_sign.encode('ascii'), hashlib.sha256).hexdigest()

    ahdr = ('AWS4-HMAC-SHA256 '
        'Credential={key}/{date}/{region}/{service}/aws4_request, '
        'SignedHeaders={headers}, Signature={sig}'.format(
            key=aws_key, date=date, region=aws_region, service=aws_service,
            headers=header_names,
            sig=sig,
        )
    )

    headers['Authorization'] = ahdr


class ObjectChunk(object):
    def __init__(self, bucket, key, firstByte, lastByte, versionId=None, partNum=None):
        if isinstance(bucket, Bucket):
            bucket = bucket._name
        self.bucket = bucket
        self.key = key
        self.firstByte = firstByte
        self.lastByte = lastByte
        self.versionId = versionId
        self.partNum = partNum


class MultipartUpload(object):
    def __init__(self, bucket, key, upload_id):
        self.bucket = bucket
        self.key = key
        self.upload_id = upload_id
        self.parts = dict()  # num -> etag
        self._done = False
        self._uri = '/' + self.key + '?uploadId=' + self.upload_id

    @asyncio.coroutine
    def add_chunk(self, data, part_num=None):
        assert isinstance(data, (bytes, memoryview, bytearray, ObjectChunk)), data

        # figure out how to check chunk size, all but last one
        # assert len(data) > 5 << 30, "Chunk must be at least 5Mb"

        if self._done:
            raise RuntimeError("Can't add_chunk after commit or close")

        if part_num is None:
            part_num = len(self.parts) + 1

        self.parts[part_num] = None

        headers = {
            # next one aiohttp adds for us anyway, so we must put it here
            # so it's added into signature
            'CONTENT-TYPE': 'application/octed-stream',
        }

        isCopy = False
        if isinstance(data, ObjectChunk):
            objChunk = data
            data = b''
            srcPath = "/{0}/{1}".format(objChunk.bucket, amz_uriencode(objChunk.key))
            if (objChunk.versionId is not None):
                srcPath = srcPath + "?versionId={0}".format(objChunk.versionId)
            headers['x-amz-copy-source'] = srcPath
            headers['x-amz-copy-source-range'] = "bytes={0}-{1}".format(objChunk.firstByte, objChunk.lastByte)
            isCopy = True

        response, xml = yield from self.bucket._request("PUT", '/' + self.key, {
                'uploadId': self.upload_id,
                'partNumber': str(part_num),
            }, headers=headers, payload=data)

        if not isCopy:
            etag = response.headers['ETAG']   # per AWS docs get the etag from the headers
        else:
            # Per AWS docs if copy case need to get the etag from the XML response
            xml = xmltodict.parse(xml)["CopyPartResult"]
            etag = xml["ETag"]
            if etag.startswith("\""): etag = etag[1:-1]

        self.parts[part_num] = etag
        
    @asyncio.coroutine
    def commit(self):
        if self._done:
            raise RuntimeError("Can't commit twice or after close")
        self._done = True

        self.parts = [{'PartNumber': n, 'ETag': etag} for n, etag in self.parts.items()]
        self.parts = sorted(self.parts, key=lambda x: x['PartNumber'])

        xml = {"CompleteMultipartUpload": {'Part': self.parts}}

        data = xmltodict.unparse(xml, full_document=False).encode('utf8')

        response, xml = yield from self.bucket._request("POST", '/' + self.key, {
                'uploadId': self.upload_id,
            }, headers={'CONTENT-TYPE': 'application/xml'}, payload=data)

        xml = xmltodict.parse(xml)['CompleteMultipartUploadResult']
        return xml

    @asyncio.coroutine
    def close(self):
        if self._done:
            return

        self._done = True

        yield from self.bucket._request("DELETE", '/' + self.key, {'uploadId': self.upload_id})


class Bucket(object):
    def __init__(self, name, *,
                 port=80,
                 aws_key, aws_secret,
                 aws_region='us-east-1',
                 aws_endpoint='s3.amazonaws.com',
                 connector=None,
                 scheme='http',
                 cred_resolver=None,
                 logger=None,
                 num_retries=5):  # method must return the tuple: (aws_key, aws_secret)
        if logger is None: logger = logging.logger('aio-s3')
        self._logger = logger
        self._name = name
        self._connector = connector
        self._num_retries = num_retries
        self._num_requests = 0

        self._aws_sign_data = {
            'aws_key': aws_key,
            'aws_secret': aws_secret,
            'aws_region': aws_region,
            'aws_service': 's3',
        }

        self._scheme = scheme
        self._host = self._name + '.' + aws_endpoint
        self._cred_resolver = cred_resolver

        if port != 80:
            self._host = self._host + ':' + str(port)

        if self._connector is None:
            self._connector = aiohttp.TCPConnector(force_close=False, keepalive_timeout=8, use_dns_cache=True)

        self._session = aiohttp.ClientSession(connector=self._connector)

    def __del__(self):
        self._session.close()  # why is this not implicit?

    def _update_creds(self):
        if not self._cred_resolver: return

        self._aws_sign_data["aws_key"], self._aws_sign_data["aws_secret"] = self._cred_resolver()

    @asyncio.coroutine
    def getLocation(self):
        response, data = yield from self._request("GET", "/", {'location': None})

        region = xmltodict.parse(data)['LocationConstraint']
        if (region is None) or (len(region) == 0):
            return 'us-east-1'

        return region

    @asyncio.coroutine
    def exists(self, prefix=''):
        response, data = yield from self._request("GET", "/", {'prefix': prefix, 'separator': '/', 'max-keys': '1'})

        x = xmltodict.parse(data)['ListBucketResult']
        return any(map(Key.from_dict, x["Contents"]))

    @asyncio.coroutine
    def list(self, prefix='', max_keys=1000):
        response, data = yield from self._request( "GET", "/", {'prefix': prefix, 'max-keys': str(max_keys)})

        x = xmltodict.parse(data)['ListBucketResult']

        if 'IsTruncated' != 'false':
            raise AssertionError("File list is truncated, use bigger max_keys")

        return list(map(Key.from_dict, _safe_list(x["Contents"])))

    def list_by_chunks(self, prefix='', max_keys=1000):
        final = False
        marker = ''

        @asyncio.coroutine
        def read_next():
            nonlocal final, marker

            response, data = yield from self._request( "GET", "/",
                {'prefix': prefix,
                 'max-keys': str(max_keys),
                 'marker': marker},
            )

            x = xmltodict.parse(data)['ListBucketResult']

            result = list(map(Key.from_dict, _safe_list(x['Contents']))) if "Contents" in x else []

            if x['IsTruncated'] == 'false' or len(result) == 0:
                final = True
            else:
                if 'NextMarker' not in x:  # amazon, really?
                    marker = result[-1].key
                else:
                    marker = x['NextMarker']

            return result

        while not final:
            yield read_next()

    @asyncio.coroutine
    def head(self, key, versionId=None):
        if isinstance(key, Key):
            key = key.key

        params = {} if versionId is None else {'versionId': versionId}
        response, xml = yield from self._request("HEAD", '/' + key, params)

        obj = {'Metadata': dict()}
        for h, v in response.headers.items():
            if not h.startswith('X-AMZ-META-'): continue
            obj['Metadata'][h[11:].lower()] = v  # boto3 returns keys in lowercase

        return obj

    @asyncio.coroutine
    def download(self, key, versionId=None):
        if isinstance(key, Key):
            key = key.key

        params = {} if versionId is None else {'versionId' : versionId}
        response, data = yield from self._request( "GET", '/' + key, params)

        return response

    @asyncio.coroutine
    def upload_file(self, key, file_path):
        data = open(file_path, 'rb').read()
        yield from self.upload(key, data, len(data))

    @asyncio.coroutine
    def upload(self, key, data, content_length=None, content_type='application/octed-stream'):
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

        headers = {'CONTENT-TYPE': content_type}

        if content_length is not None:
            headers['CONTENT-LENGTH'] = str(content_length)

        response, xml = yield from self._request("PUT", '/' + key, {},  headers=headers, payload=data)

        return response

    @asyncio.coroutine
    def delete(self, key):
        if isinstance(key, Key):
            key = key.key

        response, xml = yield from self._request("DELETE", '/' + key)

        return response

    @asyncio.coroutine
    def copy(self, copy_source, key):
        if isinstance(key, Key):
            key = key.key

        response, xml = yield from self._request("PUT", '/' + key, {}, {'x-amz-copy-source': copy_source})

        return xmltodict.parse(xml)["CopyObjectResult"]

    @asyncio.coroutine
    def get(self, key):
        if isinstance(key, Key):
            key = key.key

        response, xml = yield from self._request("GET", '/' + key)
        return xml

    @asyncio.coroutine
    def _request(self, verb, resource, query=None, headers=None, payload=b''):
        if query is None: query = dict()
        if headers is None: headers = dict()

        headers['HOST'] = self._host
        headers['CONTENT-LENGTH'] = str(len(payload))

        resource = amz_uriencode_slash(resource)
        query_string = '&'.join(k + '=' + v if v is not None else k
            for k, v in sorted((amz_uriencode(k), amz_uriencode(v) if v is not None else None)
                               for k, v in query.items()))

        self._update_creds()

        sign_v4(verb, resource, query_string, headers, payload, **self._aws_sign_data)

        url = '{0}://{1}{2}?{3}'.format(self._scheme, headers['HOST'], resource, query_string)

        response = lambda: None
        response.status = 500
        retries = 0
        chunked = 'CONTENT-LENGTH' not in headers
        data = b''

        # Note: from what I gather these errors are to be expected all the time
        #       either that or there are several connection issues in aiohttp
        #       from what I gather we usually never have to go beyond one retry
        while retries < self._num_retries:
            start = time.time()
            self._num_requests += 1

            try:
                if self._session is not None:
                    response = yield from self._session.request(verb, url, chunked=chunked, headers=headers, data=payload)
                else:
                    response = yield from aiohttp.request(verb, url, chunked=chunked, headers=headers, data=payload)

                response_elapsed = time.time() - start
            except:
                # yes, we get multiple types of exceptions
                retries += 1
                self._logger.exception('Retrying {}/{} on s3 request: {}'.format(retries, self._num_retries, url))
                if retries == self._num_retries:
                    raise

                continue

            if response != 204:
                try:
                    data = yield from response.read()
                except:
                    yield from response.wait_for_close()

            read_elapsed = time.time() - start - response_elapsed
            yield from response.wait_for_close()
            close_elapsed = time.time() - start - read_elapsed

            if response.status == 500:
                # per AWS docs you should retry a few times after receiving a 500
                retries += 1
                self._logger.warning("Retrying {}/{} error:{}".format(
                    retries, self._num_retries,errors.AWSException.from_bytes(response.status, data, url)))

                yield from asyncio.sleep(0.5)
                continue

            break

        if response.status not in [200, 204]:
            raise errors.AWSException.from_bytes(response.status, data, url)

        return response, data

    @asyncio.coroutine
    def upload_multipart(self, key,
            content_type='application/octed-stream',
            MultipartUpload=MultipartUpload,
            metadata={}):
        """Upload file to S3 by uploading multiple chunks"""

        if isinstance(key, Key):
            key = key.key

        q_obj = {'CONTENT-TYPE': content_type}

        for n, v in metadata.items():
            q_obj["x-amz-meta-" + n] = v

        response, xml = yield from self._request("POST", '/' + key, {'uploads': ''}, q_obj)

        xml = xmltodict.parse(xml)['InitiateMultipartUploadResult']
        upload_id = xml['UploadId']

        assert upload_id
        return MultipartUpload(self, key, upload_id)

    @asyncio.coroutine
    def abort_multipart_upload(self, key, upload_id):
        if isinstance(key, Key):
            key = key.key

        yield from self._request("DELETE", '/' + key, {"uploadId": upload_id})

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

            response, data = yield from self._request("GET", "/", query)

            x = xmltodict.parse(data)['ListMultipartUploadsResult']

            if x['IsTruncated'] == 'false' or len(x['Upload']) == 0:
                final = True
            else:
                key_marker = x['NextKeyMarker']
                upload_id_marker = x['NextUploadIdMarker']

            return x

        while not final:
            yield read_next()
