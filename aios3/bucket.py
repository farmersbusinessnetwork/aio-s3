import datetime
import logging
import asyncio
import xmltodict
import collections
import time
import botocore.auth
import botocore.session
import botocore.client
from functools import partial
from urllib.parse import quote
import aiohttp

from . import errors

# NOTE: if we ever enable this we'll need to support checking for signature expiration
PRESIGN_SUPPORT = False

amz_uriencode = partial(quote, safe='~')


def _safe_list(obj):
    if isinstance(obj, collections.OrderedDict):
        return [obj]
    return obj


# TODO: get rid of this Key to match botocore
class Key:
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

    async def add_chunk(self, data, part_num=None):
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
            obj_chunk = data
            data = b''
            srcPath = "/{0}/{1}".format(obj_chunk.bucket, amz_uriencode(obj_chunk.key))
            if obj_chunk.versionId is not None:
                srcPath = srcPath + "?versionId={0}".format(obj_chunk.versionId)
            headers['x-amz-copy-source'] = srcPath
            headers['x-amz-copy-source-range'] = "bytes={0}-{1}".format(obj_chunk.firstByte, obj_chunk.lastByte)
            is_copy = True

        response, xml = await self.bucket._request("PUT", '/' + self.key, {
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

    async def commit(self):
        if self._done:
            raise RuntimeError("Can't commit twice or after close")
        self._done = True

        self.parts = [{'PartNumber': n, 'ETag': etag} for n, etag in self.parts.items()]
        self.parts = sorted(self.parts, key=lambda x: x['PartNumber'])

        xml = {"CompleteMultipartUpload": {'Part': self.parts}}

        data = xmltodict.unparse(xml, full_document=False).encode('utf8')

        response, xml = await self.bucket._request("POST", '/' + self.key, {
                'uploadId': self.upload_id,
            }, headers={'CONTENT-TYPE': 'application/xml'}, payload=data)

        xml = xmltodict.parse(xml)['CompleteMultipartUploadResult']
        return xml

    async def close(self):
        if self._done:
            return

        self._done = True

        await self.bucket._request("DELETE", '/' + self.key, {'uploadId': self.upload_id})


# TODO get rid of idea of Bucket class and instead have a session that does NOT know the bucket
# to match botocore
# TODO have a generic pager, or re-use the botocore pager
# TODO have a cython signature class to reduce CPU usage (http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html)
class Bucket:
    class StatsUpdater:
        def __init__(self, bucket):
            self._bucket = bucket

        def __enter__(self):
            self._bucket._concurrent += 1
            self.start = time.time()
            return self

        def __exit__(self, exc_type, exc, exc_tb):
            now = time.time()
            self.elapsed = now - self.start
            self._bucket._concurrent -= 1
            self._bucket._request_times.append(self.elapsed)

            if (now - self._bucket._last_stat_time) > 5:
                self._bucket._last_stat_time = now

                min_time = round(min(self._bucket._request_times), 3)
                max_time = round(max(self._bucket._request_times), 3)
                avg_time = round(sum(self._bucket._request_times) / len(self._bucket._request_times), 3)
                self._bucket._logger.info("aios3 concurrency:{} lag min:{} avg:{} max:{} num:{}".format(self._bucket._concurrent, min_time, avg_time, max_time, len(self._bucket._request_times)))
                self._bucket._request_times.clear()

    def __init__(self, name, *,
                 aws_region='us-west-2',
                 connector=None,
                 scheme='http',
                 boto_creds=None,
                 logger=None,
                 num_retries=5,
                 timeout=None,
                 loop=None):
        """
        Bucket class used to access S3 buckets

        @param name: name of bucket to
        @param aws_region: AWS region to use for communication
        @param connector:
        @param scheme: http or https
        @param boto_creds: botocore credential resolver
        @param logger:
        @param num_retries: number of retries for AWS operations
        @param timeout: aiohttp timeout in seconds
        @return: aios3 Bucket object
        """

        if logger is None: logger = logging.getLogger('aio-s3')

        self._name = name
        self._connector = connector
        self._num_retries = num_retries
        self._num_requests = 0
        self._aws_region = aws_region
        self._boto_creds = boto_creds
        self._timeout = timeout
        self._logger = logger
        self._loop = loop
        self._presign_cache = dict()  # (method, params) -> url
        self._cache_hits = 0
        self._cache_misses = 0

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
            self._connector = aiohttp.TCPConnector(force_close=False, keepalive_timeout=10, use_dns_cache=False, loop=self._loop)

        self._session = aiohttp.ClientSession(connector=self._connector, loop=self._loop)
        self._signer = botocore.auth.S3SigV4Auth(self._boto_creds, 's3', self._aws_region)

        if PRESIGN_SUPPORT:
            boto_session = botocore.session.get_session()
            config = botocore.client.Config(signature_version='s3v4')
            use_ssl = self._scheme == 'https'
            self._boto_client = boto_session.create_client('s3', region_name=aws_region, use_ssl=use_ssl, config=config)

        # stats support
        self._concurrent = 0
        self._last_stat_time = time.time()
        self._request_times = []

    def __del__(self):
        self._session.close()  # why is this not implicit?

    async def getLocation(self):
        response, data = await self._request("GET", "/", params={'location': ''})

        region = xmltodict.parse(data)['LocationConstraint']
        if (region is None) or (len(region) == 0):
            return 'us-east-1'

        return region

    async def exists(self, prefix=''):
        response, data = await self._request("GET", "/", {'prefix': prefix, 'separator': '/', 'max-keys': '1'})

        x = xmltodict.parse(data)['ListBucketResult']
        return any(map(Key.from_dict, x["Contents"]))

    async def list(self, prefix='', delimiter=None, max_keys=1000, boto_style=False):
        params = {
            'prefix': prefix,
            'max-keys': str(max_keys)
        }

        if delimiter:
            params['delimiter'] = delimiter

        response, data = await self._request("GET", "/", params)

        x = xmltodict.parse(data)['ListBucketResult']

        if x['IsTruncated'] != 'false':
            raise AssertionError("File list is truncated, use bigger max_keys")

        if boto_style:
            if 'Contents' in x and not isinstance(x['Contents'], list):
                x['Contents'] = [x['Contents']]

            if 'CommonPrefixes' in x and not isinstance(x['CommonPrefixes'], list):
                x['CommonPrefixes'] = [x['CommonPrefixes']]

            return x
        else:
            return list(map(Key.from_dict, _safe_list(x["Contents"])))

    def list_by_chunks(self, prefix='', delimiter=None, boto_style=False, max_keys=1000):
        class Pager:
            def __init__(self, bucket: Bucket, prefix='', delimiter=None, boto_style=False, max_keys=1000):
                self.bucket = bucket
                self.final = False
                self.marker = ''
                self.prefix = prefix
                self.delimiter = delimiter
                self.boto_style = boto_style
                self.max_keys = max_keys

            async def __anext__(self):
                if self.final: raise StopAsyncIteration
                return await self.next_page()

            async def __aiter__(self):
                return self

            async def next_page(self):
                if self.final: return None

                params = {
                    'prefix': self.prefix,
                    'max-keys': str(max_keys),
                    'marker': self.marker,
                    'encoding-type': 'url'
                }

                if delimiter:
                    params['delimiter'] = delimiter

                response, data = await self.bucket._request("GET", "/", params)

                x = xmltodict.parse(data)['ListBucketResult']

                if self.boto_style:
                    if 'Contents' in x and not isinstance(x['Contents'], list):
                        x['Contents'] = [x['Contents']]

                    if 'CommonPrefixes' in x and not isinstance(x['CommonPrefixes'], list):
                        x['CommonPrefixes'] = [x['CommonPrefixes']]

                    result = x
                else:
                    result = list(map(Key.from_dict, _safe_list(x['Contents']))) if "Contents" in x else []

                if x['IsTruncated'] == 'false' or len(result) == 0:
                    self.final = True
                else:
                    if 'NextMarker' not in x:  # amazon, really?
                        if self.boto_style:
                            self.marker = result['Contents'][-1]['Key']
                        else:
                            self.marker = result[-1].key
                    else:
                        self.marker = x['NextMarker']

                return x

        return Pager(self, prefix, delimiter, boto_style, max_keys)

    async def head(self, key, versionId=None):
        if isinstance(key, Key):
            key = key.key

        params = {} if versionId is None else {'versionId': versionId}
        response, xml = await self._request("HEAD", '/' + key, params)

        obj = {'Metadata': dict()}
        for h, v in response.headers.items():
            if not h.startswith('X-AMZ-META-'): continue
            obj['Metadata'][h[11:].lower()] = v  # boto3 returns keys in lowercase

        return obj

    async def download(self, key, versionId=None):
        if isinstance(key, Key):
            key = key.key

        params = {} if versionId is None else {'versionId' : versionId}
        response, data = await self._request("GET", '/' + key, params)

        return response

    async def upload_file(self, key, file_path):
        data = open(file_path, 'rb').read()
        await self.upload(key, data, len(data))

    async def upload(self, key, data, content_length=None, content_type='application/octed-stream'):
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

        response, xml = await self._request("PUT", '/' + key, {},  headers=headers, payload=data)

        return xml, dict(response.headers)

    async def delete(self, key):
        if isinstance(key, Key):
            key = key.key
        response, xml = await self._request("DELETE", '/' + key)

        return xml

    async def copy(self, copy_source, key):
        if isinstance(key, Key):
            key = key.key

        response, xml = await self._request("PUT", '/' + key, {}, {'x-amz-copy-source': copy_source})

        return xmltodict.parse(xml)["CopyObjectResult"]

    async def get(self, key):
        if isinstance(key, Key):
            key = key.key

        if PRESIGN_SUPPORT:
            pre_key = ('get_object', {'Bucket': self._name, 'Key': key})
            try:
                ps_url = self._presign_cache[key]
                self._cache_hits += 1
            except:
                self._cache_misses += 1
                ps_url = self._boto_client.generate_presigned_url(pre_key[0], Params=pre_key[1])
                self._presign_cache[key] = ps_url

            response, data = await self._request("GET", None, presigned_url=ps_url)
        else:
            response, data = await self._request("GET", '/' + key)

        return data, dict(response.headers)

    async def _request(self, method, resource, params=None, headers=None, payload=b'', presigned_url=None):
        if presigned_url:
            url = presigned_url
        else:
            url = '{}://{}{}'.format(self._scheme, self._endpoint, resource)

            if headers is None: headers = dict()

            headers['host'] = self._host
            headers['CONTENT-LENGTH'] = str(len(payload)) if payload else '0'

        class S3Request:
            def __init__(self, in_headers, in_params, in_body, in_method, in_url):
                self.headers = in_headers
                self.params = in_params if in_params else dict()
                self.context = dict()
                self.body = in_body
                self.method = in_method
                self.url = in_url

            def __str__(self):
                return "method:{} url:{} headers:{} params:{}".format(self.method, self.url, self.headers, self.params)

        response = lambda: None
        response.status = 500
        retries = 0
        data = b''
        next_wait = 0.1

        # Note: from what I gather these errors are to be expected all the time
        #       either that or there are several connection issues in aiohttp
        #       also from what I've seen we usually never have to go beyond one retry
        with Bucket.StatsUpdater(self) as su:
            while retries < self._num_retries:
                self._num_requests += 1
                if not presigned_url:
                    req = S3Request(headers, params, payload, method, url)
                    self._signer.add_auth(req)

                try:
                    if self._timeout is not None:
                        with aiohttp.Timeout(self._timeout):
                            async with self._session.request(req.method, req.url, params=req.params, headers=req.headers, data=req.body) as response:
                                async with response:
                                    data = await response.read()
                    else:
                        async with self._session.request(req.method, req.url, params=req.params, headers=req.headers, data=req.body) as response:
                            async with response:
                                if response != 204:
                                    data = await response.read()
                except (KeyboardInterrupt, SystemExit, MemoryError):
                    raise
                except:
                    retries += 1
                    self._logger.info('Retrying {}/{} request:{}'.format(retries, self._num_retries, req))
                    if retries == self._num_retries:
                        raise
                    continue

                if response.status == 500:
                    # per AWS docs you should retry a few times after receiving a 500
                    retries += 1
                    err = errors.AWSException.from_bytes(response.status, data, url)
                    self._logger.warning("Retrying {}/{} request:{} error:{}".format(retries, self._num_retries, req, err))

                    await asyncio.sleep(next_wait)

                    if isinstance(err, errors.SlowDown) or isinstance(err, errors.InternalError):
                        next_wait *= 5  # 0.1->0.5->2.5->12.5->62.5

                    continue

                break

        if response.status not in [200, 204]:
            raise errors.AWSException.from_bytes(response.status, data, url)

        return response, data

    async def upload_multipart(self, key,
            content_type='application/octed-stream',
            MultipartUpload=MultipartUpload,
            metadata={}):
        """Upload file to S3 by uploading multiple chunks"""

        if isinstance(key, Key):
            key = key.key

        headers = {'CONTENT-TYPE': content_type}
        for n, v in metadata.items():
            headers["x-amz-meta-" + n] = v

        response, xml = await self._request("POST", '/' + key, params={'uploads': ''}, headers=headers)

        xml = xmltodict.parse(xml)['InitiateMultipartUploadResult']
        upload_id = xml['UploadId']

        assert upload_id
        return MultipartUpload(self, key, upload_id)

    async def abort_multipart_upload(self, key, upload_id):
        if isinstance(key, Key):
            key = key.key

        await self._request("DELETE", '/' + key, {"uploadId": upload_id})

    def list_multipart_uploads_by_chunks(self, prefix='', max_uploads=1000):
        final = False
        key_marker = ''
        upload_id_marker = ''

        async def read_next():
            nonlocal final, key_marker, upload_id_marker

            query = {'max-uploads': str(max_uploads), 'uploads': ''}
            if len(prefix):
                query['prefix'] = prefix

            if len(key_marker):
                query['key-marker'] = key_marker
                query['upload-id-market'] = upload_id_marker

            response, data = await self._request("GET", "/", query)

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
