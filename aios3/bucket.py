import datetime
import logging
import asyncio
import xmltodict
import collections
import time
import botocore.auth

from functools import partial
from urllib.parse import quote

import aiohttp

from . import errors

amz_uriencode = partial(quote, safe='~')


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

        is_copy = False
        if isinstance(data, ObjectChunk):
            objChunk = data
            data = b''
            srcPath = "/{0}/{1}".format(objChunk.bucket, amz_uriencode(objChunk.key))
            if objChunk.versionId is not None:
                srcPath = srcPath + "?versionId={0}".format(objChunk.versionId)
            headers['x-amz-copy-source'] = srcPath
            headers['x-amz-copy-source-range'] = "bytes={0}-{1}".format(objChunk.firstByte, objChunk.lastByte)
            is_copy = True

        response, xml = yield from self.bucket._request("PUT", '/' + self.key, {
                'uploadId': self.upload_id,
                'partNumber': str(part_num),
            }, headers=headers, payload=data)

        if not is_copy:
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
                 aws_key=None, aws_secret=None,
                 aws_region='us-east-1',
                 connector=None,
                 scheme='http',
                 boto_creds=None,
                 logger=None,
                 num_retries=5):  # method must return the tuple: (aws_key, aws_secret)

        if (aws_key is None or aws_secret is None) and boto_creds is None:
            raise Exception('You must specify aws_key/aws_secret or boto_creds')

        if logger is None: logger = logging.logger('aio-s3')

        # TODO: should deprecate aws_key/aws_secret
        if boto_creds is None:
            class Creds:
                def __init__(self):
                    self.secret_key = aws_secret
                    self.access_key = aws_key
                    self.token = None

            boto_creds = Creds()

        self._logger = logger
        self._name = name
        self._connector = connector
        self._num_retries = num_retries
        self._num_requests = 0
        self._aws_region = aws_region
        self._boto_creds = boto_creds

        # Virtual style host URL
        # ----------------------
        #   endpoint: bucket.s3.amazonaws.com / bucket.s3-aws-region.amazonaws.com
        #   host: bucket.s3.amazonaws.com
        #
        # Path Style
        # ----------
        #   endpoint:  s3.amazonaws.com/bucket / s3-aws-region.amazonaws.com/bucket
        #       host: s3.amazonaws.com
        #

        # We use Path Style because the Amazon SSL wildcard cert will not match for virtual style with buckets
        # that have '.'s: http://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html

        self._scheme = scheme
        self._host = "s3-" + aws_region + ".amazonaws.com"
        self._endpoint = self._host + "/" + self._name

        if self._connector is None:
            self._connector = aiohttp.TCPConnector(force_close=False, keepalive_timeout=10, use_dns_cache=True)

        self._session = aiohttp.ClientSession(connector=self._connector)

    def __del__(self):
        self._session.close()  # why is this not implicit?

    @asyncio.coroutine
    def getLocation(self):
        response, data = yield from self._request("GET", "/", params={'location': ''})

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
        response, data = yield from self._request("GET", "/", {'prefix': prefix, 'max-keys': str(max_keys)})

        x = xmltodict.parse(data)['ListBucketResult']

        if x['IsTruncated'] != 'false':
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
    def _request(self, method, resource, params=None, headers=None, payload=b''):
        if params is None: params = dict()
        if headers is None: headers = dict()

        headers['HOST'] = self._host
        headers['CONTENT-LENGTH'] = str(len(payload))

        url = '{}://{}{}'.format(self._scheme, self._endpoint, resource)

        class S3Request:
            def __init__(self):
                self.headers = headers
                self.params = params
                self.context = dict()
                self.body = payload
                self.method = method
                self.url = url

        signer = botocore.auth.S3SigV4Auth(self._boto_creds, 's3', self._aws_region)
        req = S3Request()
        signer.add_auth(req)

        response = lambda: None
        response.status = 500
        retries = 0
        data = b''

        # Note: from what I gather these errors are to be expected all the time
        #       either that or there are several connection issues in aiohttp
        #       from what I gather we usually never have to go beyond one retry
        while retries < self._num_retries:
            start = time.time()
            self._num_requests += 1

            try:
                response = yield from self._session.request(req.method, req.url, params=req.params, headers=req.headers, data=req.body)
                response_elapsed = time.time() - start
            except:
                # yes, we get multiple types of exceptions
                retries += 1
                self._logger.warning('Retrying {}/{} on s3 request: {}'.format(retries, self._num_retries, url))
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

        headers = {'CONTENT-TYPE': content_type}
        for n, v in metadata.items():
            headers["x-amz-meta-" + n] = v

        response, xml = yield from self._request("POST", '/' + key, params={'uploads': ''}, headers=headers)

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

            query = {'max-uploads': str(max_uploads), 'uploads':''}
            if len(prefix):
                query['prefix'] = prefix

            if len(key_marker):
                query['key-marker'] = key_marker
                query['upload-id-market'] = upload_id_marker

            response, data = yield from self._request("GET", "/", query)

            x = xmltodict.parse(data)['ListMultipartUploadsResult']
            if 'Upload' not in x: x['Upload'] = []

            if x['IsTruncated'] == 'false' or len(x['Upload']) == 0:
                final = True
            else:
                key_marker = x['NextKeyMarker']
                upload_id_marker = x['NextUploadIdMarker']

            return x

        while not final:
            yield read_next()
