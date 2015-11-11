from xml.etree.ElementTree import ParseError
import xmltodict

class AWSException(Exception):
    """Base for exceptions returned by amazon"""

    @staticmethod
    def from_bytes(status, body, url=None):
        if not body:
            # sometimes Riak CS doesn't have response body :(
            # TODO(tailhook) maybe use status to create specific error?
            if status != 404:
                raise RuntimeError("HTTP Error {}".format(status))
            else:
                raise NotFound()
        try:
            xml = xmltodict.parse(body)

        except:
            raise RuntimeError(body)

        error = xml['Error'] if 'Error' in xml else None

        class_name = error['Code'] if 'Code' in error else None
        if class_name is None or not len(class_name):
            raise RuntimeError(body)

        try:
            cls = globals()[class_name]
        except KeyError:
            raise RuntimeError("Error {} is unknown".format(class_name))

        msg = error['Message'] if 'Message' in error else class_name
        if url is not None:
            msg = url + " " + msg
        return cls(msg)


class NotFound(Exception): pass

class AccessDenied(AWSException): pass
class AccountProblem(AWSException): pass
class AmbiguousGrantByEmailAddress(AWSException): pass
class AuthorizationHeaderMalformed(AWSException): pass
class BadDigest(AWSException): pass
class BucketAlreadyExists(AWSException): pass
class BucketAlreadyOwnedByYou(AWSException): pass
class BucketNotEmpty(AWSException): pass
class CredentialsNotSupported(AWSException): pass
class CrossLocationLoggingProhibited(AWSException): pass
class EntityTooSmall(AWSException): pass
class EntityTooLarge(AWSException): pass
class ExpiredToken(AWSException): pass
class IllegalVersioningConfigurationException(AWSException): pass
class IncompleteBody(AWSException): pass
class IncorrectNumberOfFilesInPostRequest(AWSException): pass
class InlineDataTooLarge(AWSException): pass
class InternalError(AWSException): pass
class InvalidAccessKeyId(AWSException): pass
class InvalidAddressingHeader(AWSException): pass
class InvalidArgument(AWSException): pass
class InvalidBucketName(AWSException): pass
class InvalidBucketState(AWSException): pass
class InvalidDigest(AWSException): pass
class InvalidEncryptionAlgorithmError(AWSException): pass
class InvalidLocationConstraint(AWSException): pass
class InvalidObjectState(AWSException): pass
class InvalidPart(AWSException): pass
class InvalidPartOrder(AWSException): pass
class InvalidPayer(AWSException): pass
class InvalidPolicyDocument(AWSException): pass
class InvalidRange(AWSException): pass
class InvalidRequest(AWSException): pass
class InvalidSecurity(AWSException): pass
class InvalidSOAPRequest(AWSException): pass
class InvalidStorageClass(AWSException): pass
class InvalidTargetBucketForLogging(AWSException): pass
class InvalidToken(AWSException): pass
class InvalidURI(AWSException): pass
class KeyTooLong(AWSException): pass
class MalformedACLError(AWSException): pass
class MalformedPOSTRequest(AWSException): pass
class MalformedXML(AWSException): pass
class MaxMessageLengthExceeded(AWSException): pass
class MaxPostPreDataLengthExceededError(AWSException): pass
class MetadataTooLarge(AWSException): pass
class MethodNotAllowed(AWSException): pass
class MissingAttachment(AWSException): pass
class MissingContentLength(AWSException): pass
class MissingRequestBodyError(AWSException): pass
class MissingSecurityElement(AWSException): pass
class MissingSecurityHeader(AWSException): pass
class NoLoggingStatusForKey(AWSException): pass
class NoSuchBucket(AWSException): pass
class NoSuchKey(AWSException): pass
class NoSuchLifecycleConfiguration(AWSException): pass
class NoSuchUpload(AWSException): pass
class NoSuchVersion(AWSException): pass
class NotImplemented(AWSException): pass
class NotSignedUp(AWSException): pass
class NotSuchBucketPolicy(AWSException): pass
class OperationAborted(AWSException): pass
class PermanentRedirect(AWSException): pass
class PreconditionFailed(AWSException): pass
class Redirect(AWSException): pass
class RestoreAlreadyInProgress(AWSException): pass
class RequestIsNotMultiPartContent(AWSException): pass
class RequestTimeout(AWSException): pass
class RequestTimeTooSkewed(AWSException): pass
class RequestTorrentOfBucketError(AWSException): pass
class SignatureDoesNotMatch(AWSException): pass
class ServiceUnavailable(AWSException): pass
class SlowDown(AWSException): pass
class TemporaryRedirect(AWSException): pass
class TokenRefreshRequired(AWSException): pass
class TooManyBuckets(AWSException): pass
class UnexpectedContent(AWSException): pass
class UnresolvableGrantByEmailAddress(AWSException): pass
class UserKeyMustBeSpecified(AWSException): pass
