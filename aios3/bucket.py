import logging
import asyncio
import xmltodict
import collections
import time
from functools import partial
from urllib.parse import quote
import aiohttp
import hashlib
import base64
import functools

import botocore.auth
import botocore.exceptions
import botocore.session
import botocore.client
import botocore.credentials
from botocore.handlers import parse_get_bucket_location

import aiobotocore  # we use this to parse the response, it needs to be aiobotocore due to the aiohttp response object
import aiobotocore.client
from aiobotocore.endpoint import convert_to_response_dict

# NOTE: if we ever enable this we'll need to support checking for signature expiration
PRESIGN_SUPPORT = False

amz_uriencode = partial(quote, safe='~')


def _safe_list(obj):
    if isinstance(obj, collections.OrderedDict):
        return [obj]
    return obj


# async io exponential delay retry handler
class _RetryHandler:
    _delay_multiplier = 5
    _initial_delay = 0.1

    def __init__(self, num_retries, timeout):
        self._max_retries = num_retries
        self._retry_num = 0  # first "retry" is actually the first request with 0 delay
        self._delay = self._initial_delay
        self._timeout = timeout

    @property
    def retry_num(self):
        return self._retry_num

    @property
    def max_retries(self):
        return self._max_retries

    # exponential function: y = k(m^x) where k is initial value, m is multiplier, x is number of iterations
    def max_timeout(self):
        # maximum total delay + maximum total timeout for each request
        delay = 0
        for i in range(self._max_retries):
            delay += self._initial_delay * (self._delay_multiplier ** i)
        return delay + (self._timeout * (self._max_retries + 1))

    def can_retry(self):
        return self._retry_num < (self._max_retries + 1)  # plus initial request

    async def retry(self):
        """ Will asyncio.sleep and return True during allowable retries, otherwise return False """
        if self._retry_num < (self._max_retries + 1):  # plus initial request
            if self._retry_num != 0:
                await asyncio.sleep(self._delay)
                self._delay *= 5  # 0->0.1->0.5->2.5->12.5->62.5->etc
            self._retry_num += 1
            return True

        return False


def get_maximum_timeout(timeout: float or int, max_attempts: int) -> float:
    """
    Will return the maximum combined timeout based on the maximum number of attempts
    :param timeout: timeout in seconds per request
    :param max_attempts: maximum number of attempts
    :return: maximimum combined timeout in seconds
    """
    rh = _RetryHandler(max_attempts, timeout)
    return rh.max_timeout()


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

        if isinstance(data, ObjectChunk):
            obj_chunk = data
            data = b''
            src_path = "/{0}/{1}".format(obj_chunk.bucket, amz_uriencode(obj_chunk.key))
            if obj_chunk.versionId is not None:
                src_path += "?versionId={0}".format(obj_chunk.versionId)
            headers['x-amz-copy-source'] = src_path
            headers['x-amz-copy-source-range'] = "bytes={0}-{1}".format(obj_chunk.firstByte, obj_chunk.lastByte)
            op_name = 'UploadPartCopy'
        else:
            op_name = 'UploadPart'

        response = await self.bucket._request("PUT", '/' + self.key, op_name, {
                'uploadId': self.upload_id,
                'partNumber': str(part_num),
            }, headers=headers, payload=data)

        if op_name == "UploadPartCopy":
            self.parts[part_num] = response['CopyPartResult']['ETag']
        else:
            self.parts[part_num] = response['ETag']

    async def commit(self):
        if self._done:
            raise RuntimeError("Can't commit twice or after close")

        self._done = True
        self.parts = [{'PartNumber': n, 'ETag': etag} for n, etag in self.parts.items()]
        self.parts = sorted(self.parts, key=lambda x: x['PartNumber'])

        xml = {"CompleteMultipartUpload": {'Part': self.parts}}

        data = xmltodict.unparse(xml, full_document=False).encode('utf8')

        response = await self.bucket._request("POST", '/' + self.key, 'CompleteMultipartUpload', {
                'uploadId': self.upload_id,
            }, headers={'CONTENT-TYPE': 'application/xml'}, payload=data)

        return response

    async def close(self):
        if self._done:
            return

        self._done = True

        return await self.bucket._request("DELETE", '/' + self.key, 'AbortMultipartUpload', {'uploadId': self.upload_id})


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
                 num_retries=6,
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
        self._retry_handler = functools.partial(_RetryHandler, timeout=self._timeout)
        self._scheme = scheme
        self._aio_boto_session = None

        # Virtual style host URL
        # ----------------------
        #   endpoint: bucket.s3.amazonaws.com / bucket.s3-aws-region.amazonaws.com
        #   host: bucket.s3.amazonaws.com
        #
        # Path Style
        # ----------
        #   endpoint: s3.amazonaws.com/bucket / s3-aws-region.amazonaws.com/bucket
        #   host: s3.amazonaws.com
        #

        # We use Path Style because the Amazon SSL wildcard cert will not match for virtual style with buckets
        # that have '.'s: http://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html

        if aws_region == 'us-east-1':
            self._host = "s3.amazonaws.com"
        else:
            self._host = "s3-" + aws_region + ".amazonaws.com"

        self._endpoint = self._host + "/" + self._name

        if self._connector is None:
            kwargs = {}
            if timeout:
                kwargs['conn_timeout'] = timeout

            self._connector = aiohttp.TCPConnector(force_close=False, keepalive_timeout=10, use_dns_cache=False, loop=self._loop, **kwargs)

        use_ssl = self._scheme == 'https'

        connector_args = {
            'use_dns_cache': self._connector._use_dns_cache,
            'force_close': self._connector._force_close,
            'keepalive_timeout': self._connector._keepalive_timeout}

        aio_config = aiobotocore.client.AioConfig(signature_version='s3v4', connector_args=connector_args)

        self._aio_boto_session = aiobotocore.get_session(loop=self._loop)
        self._aio_boto_client = self._aio_boto_session.create_client('s3', region_name=self._aws_region, config=aio_config, use_ssl=use_ssl)

        self._parsers = dict()  # OpName: (op_model, parser) map

        if self._boto_creds is None:
            self._boto_creds = botocore.credentials.create_credential_resolver(self._aio_boto_session).load_credentials()

        self._session = aiohttp.ClientSession(connector=self._connector, loop=self._loop, response_class=aiobotocore.endpoint.ClientResponseProxy)
        self._signer = botocore.auth.S3SigV4Auth(self._boto_creds, 's3', self._aws_region)

        # stats support
        self._concurrent = 0
        self._last_stat_time = time.time()
        self._request_times = []

    def __del__(self):
        self._aio_boto_client.close()
        self._session.close()  # why is this not implicit?

    async def _parse_response(self, operation_name: str, http_response: aiohttp.ClientResponse):
        parser = self._parsers.get(operation_name, None)
        if parser is None:
            operation_model = self._aio_boto_client.meta.service_model.operation_model(operation_name)
            response_parser_factory = self._aio_boto_session.get_component('response_parser_factory')
            parser = operation_model, response_parser_factory.create_parser(operation_model.metadata['protocol'])
            self._parsers[operation_name] = parser

        operation_model, parser = parser

        response_dict = await convert_to_response_dict(http_response, operation_model)
        parsed_response = parser.parse(response_dict, operation_model.output_shape)
        if operation_name == "GetBucketLocation":
            parse_get_bucket_location(parsed_response, http_response)

        if http_response.status >= 300:
            raise botocore.exceptions.ClientError(parsed_response, operation_name)

        return parsed_response

    async def get_location(self):
        response = await self._request("GET", "/", 'GetBucketLocation', params={'location': ''})
        return response

    async def exists(self, prefix=''):
        response = await self._request("GET", "/", 'ListObjects', {'prefix': prefix, 'separator': '/', 'max-keys': '1'})

        return len(response["Contents"]) > 0

    async def list_object_versions(self, Delimiter=None, KeyMarker=None, Prefix=None, VersionIdMarker=None, MaxKeys=None):
        params = {'versions': ''}

        if Delimiter is not None:
            params['delimiter'] = Delimiter
        if KeyMarker is not None:
            params['key-marker'] = KeyMarker
        if MaxKeys is not None:  # default is 1000
            params['max-keys'] = MaxKeys
        if Prefix is not None:
            params['prefix'] = Prefix
        if VersionIdMarker is not None:
            params['VersionIdMarker'] = VersionIdMarker

        response = await self._request("GET", "/", 'ListObjectVersions', params)
        return response

    async def list(self, Prefix='', Delimiter=None, MaxKeys=1000, Marker=None, allow_truncated=False):
        params = {
            'prefix': Prefix,
            'max-keys': str(MaxKeys),

            # If you need to support extended characters enable this and then url decode the Key
            # 'encoding-type': 'url'
        }

        if Marker is not None:
            params['marker'] = Marker

        if Delimiter is not None:
            params['delimiter'] = Delimiter

        response = await self._request("GET", "/", 'ListObjects', params)

        if response['IsTruncated'] and not allow_truncated:
            raise AssertionError("File list is truncated, use bigger max_keys")

        return response

    def list_by_chunks(self, Prefix='', Delimiter=None, MaxKeys=1000):
        class Pager:
            def __init__(self, bucket: Bucket):
                self.bucket = bucket
                self.final = False
                self.marker = ''
                self.prefix = Prefix

            async def __anext__(self):
                if self.final: raise StopAsyncIteration
                return await self.next_page()

            async def __aiter__(self):
                return self

            async def next_page(self):
                if self.final: return None

                result = await self.bucket.list(Prefix, Delimiter, allow_truncated=True, Marker=self.marker, MaxKeys=MaxKeys)

                if not result['IsTruncated']:
                    self.final = True
                else:
                    if 'NextMarker' in result:
                        self.marker = result['NextMarker']
                    else:
                        self.marker = result['Contents'][-1]['Key']

                return result

        return Pager(self)

    async def head(self, Key, VersionId=None):
        params = {} if VersionId is None else {'versionId': VersionId}
        response = await self._request("HEAD", '/' + Key, 'HeadObject', params)

        return response

    async def download(self, Key, VersionId=None):
        params = {} if VersionId is None else {'versionId': VersionId}
        response = await self._request("GET", '/' + Key, 'GetObject', params)

        return response

    async def upload_file(self, key, file_path):
        data = open(file_path, 'rb').read()
        await self.upload(key, data, len(data))

    async def upload(self, Key, Body, ContentLength=None, ContentType=None, Metadata=None, num_retries=None):
        """Upload file to S3

        The `data` might be a generator or stream.

        the `content_length` is unchecked so it's responsibility of user to
        ensure that it matches data.

        Note: Riak CS doesn't allow to upload files without content_length.
        """
        if isinstance(Body, str):
            Body = Body.encode('utf-8')

        headers = dict()

        if ContentType is not None:
            headers['CONTENT-TYPE'] = ContentType

        if ContentLength is not None:
            headers['CONTENT-LENGTH'] = str(ContentLength)

        if Metadata:
            for k, v in Metadata:
                headers['x-amz-meta-' + k] = str(v)

        response = await self._request("PUT", '/' + Key, 'PutObject', headers=headers, payload=Body, request_retries=num_retries)
        return response

    async def delete(self, Key):
        response = await self._request("DELETE", '/' + Key, 'DeleteObject')
        return response

    # boto style
    async def delete_objects(self, Delete, MFA=None, RequestPayer=None):
        assert not RequestPayer

        body_dict = {'Delete': {'Object': []}}

        if 'Quiet' in Delete:
            body_dict['Delete']['Quiet'] = "true" if Delete['Quiet'] else "false"

        for o in Delete['Objects']:
            body_dict['Delete']['Object'].append(o)

        body = xmltodict.unparse(body_dict).encode('utf-8')

        md5 = hashlib.md5(body).digest()
        md5 = base64.b64encode(md5).decode('ISO-8859-1')
        headers = {'Content-MD5': md5}

        if MFA:
            headers['x-amz-mfa'] = MFA

        params = {'delete': ''}
        response = await self._request("POST", '/', 'DeleteObjects', params=params, headers=headers, payload=body)
        return response

    async def copy(self, CopySource, Key):
        response = await self._request("PUT", '/' + Key, 'CopyObject', headers={'x-amz-copy-source': CopySource})
        return response

    async def get(self, Key, IfMatch=None, Range=None, VersionId=None, num_retries=None):

        headers = dict()
        params = {} if VersionId is None else {'versionId': VersionId}

        if IfMatch is not None:
            headers['If-Match'] = IfMatch
        if Range is not None:
            headers['Range'] = Range

        response = await self._request("GET", '/' + Key, 'GetObject', params=params, headers=headers, request_retries=num_retries)

        return response

    async def _request(self, method: str, resource: str, op_name: str, params=None, headers=None, payload=b'', presigned_url=None, request_retries: None or int=None):
        # we need to pre-encode the url because the signature needs to match the final url
        resource = quote(resource)

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

        # TODO: perhaps switch to client._endpoint._needs_retry
        if request_retries is None:
            request_retries = self._num_retries
        retry_handler = self._retry_handler(request_retries)

        # Note: from what I gather these errors are to be expected all the time
        #       either that or there are several connection issues in aiohttp
        #       also from what I've seen we usually never have to go beyond one retry
        with Bucket.StatsUpdater(self):
            while await retry_handler.retry() and response.status not in [200, 204]:
                self._num_requests += 1

                req = S3Request(headers, params, payload, method, url)

                if not presigned_url:
                    self._signer.add_auth(req)

                try:
                    response = await asyncio.wait_for(self._session.request(method=req.method, url=req.url, params=req.params, headers=req.headers, data=req.body),
                                                       self._timeout, loop=self._loop)

                    parsed_response = await self._parse_response(op_name, response)
                except (KeyboardInterrupt, SystemExit, MemoryError, asyncio.CancelledError):
                    raise
                except botocore.exceptions.ClientError as e:
                    if not retry_handler.can_retry() or e.response['ResponseMetadata']['HTTPStatusCode'] in [404, 412]:
                        raise

                    self._logger.warning('Retrying {}/{} request:{} exception:{}'.format(retry_handler.retry_num, retry_handler.max_retries, req, e))
                except Exception as e:
                    if not retry_handler.can_retry():
                        raise

                    self._logger.warning('Retrying {}/{} request:{} exception:{}'.format(retry_handler.retry_num, retry_handler.max_retries, req, e))

        return parsed_response

    async def upload_multipart(self, Key, content_type='application/octed-stream',
                               MultipartUpload=MultipartUpload, metadata=None):
        """Upload file to S3 by uploading multiple chunks"""

        headers = {'CONTENT-TYPE': content_type}
        if metadata is None: metadata = dict()
        for n, v in metadata.items():
            headers["x-amz-meta-" + n] = v

        response = await self._request("POST", '/' + Key, 'CreateMultipartUpload', params={'uploads': ''}, headers=headers)

        upload_id = response['UploadId']

        assert upload_id
        return MultipartUpload(self, Key, upload_id)

    async def abort_multipart_upload(self, Key, upload_id):
        return await self._request("DELETE", '/' + Key, 'AbortMultipartUpload', {"uploadId": upload_id})

    def list_multipart_uploads_by_chunks(self, Prefix='', max_uploads=1000):
        class _Pager:
            def __init__(self, parent: Bucket):
                self._parent = parent
                self._final = False
                self._key_marker = ''
                self._upload_id_marker = ''

            async def next_page(self):
                params = {'max-uploads': str(max_uploads), 'uploads': ''}
                if len(Prefix):
                    params['prefix'] = Prefix

                if len(self._key_marker):
                    params['key-marker'] = self._key_marker
                    params['upload-id-marker'] = self._upload_id_marker

                response = await self._parent._request("GET", "/", 'ListMultipartUploads', params)

                if 'Uploads' not in response: response['Uploads'] = []

                if not response['IsTruncated'] or len(response['Uploads']) == 0:
                    self._final = True
                else:
                    self._key_marker = response['NextKeyMarker']
                    self._upload_id_marker = response['NextUploadIdMarker']

                return response

            async def __anext__(self):
                if self._final: raise StopAsyncIteration
                return await self.next_page()

            async def __aiter__(self):
                return self

        return _Pager(self)
