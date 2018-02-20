#!/usr/bin/python
"""
This is a Python client for the Lastline Analyst API.

The :py:class:`AnalysisClient` class implements the client side of the Lastline Analyst API
methods. It can be imported into Python client code that uses the API.

The client is available at https://analysis.lastline.com/docs/llapi_client/analysis_apiclient.py .

Requirements
+++++++++++++++++++

The Analysis API client requires:

- Python 2.7.
- The python requests module (tested with version 2.2.1).
- The python pycurl module (tested with version 7.19.0).
- The python simplejson module (tested with version 3.6.5).
- To use the client as a python shell, the ipython module (tested with version 2.4.1).

Required python modules can be installed using tools such as apt, pip, or easy_install, e.g.::

    apt-get install python-pycurl=7.19.0-4ubuntu3
    pip install ipython==2.4.1
    easy_install requests==2.2.1

.. note::

    You may want to consider installing the API client and its dependencies inside an isolated
    environment, such as a container, schroot, or VirtualEnv. This allows experimenting with the
    Lastline APIs without affecting system libraries/modules.

Changelog
+++++++++++++++++++++++

The changelog only reflects backwards-incompatible changes; new functionality
may not be reflected in all cases

- 2016-10-05: Stop download of full report details during submission
      Submission functions, such as ``submit_file()``, ``submit_file_hash()``,
      or ``submit_url()``, now default to
      ``full_report_score=ANALYSIS_API_NO_REPORT_DETAILS`` (constant for -1),
      which disables automatic download of the full, detailed analysis report
      if a cached result is immediately available.
      To access the full analysis report, use ``get_result()`` with the task_uuid
      returned as part of the submission result.

- 2016-10-28: Move API client shell to dedicated script.
      The API client shell is now available via analysis_apiclient_shell.py, which povides
      easier access to helper modules provided by the API client module.

Analysis Client Shell
+++++++++++++++++++++++

In addition to the client, an API shell allows running the client from the command line. This
provides an interactive shell for manually sending requests to the Lastline Analyst
API, and it can be used to experiment with the API for analyzing files or URLs. For details,
refer to the :ref:`API Client Shell documentation <analysis_client_shell>`.
"""
import collections
import datetime
import sys
import time
from os import path
import logging
import hashlib
import simplejson
import requests
import cgi
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
    import io as stringIOModule

try:
    from llapi_client import get_proxies_from_config
except ImportError:
    # Non-Lastline environment. Reading from config not support/needed.
    get_proxies_from_config = None

try:
    requests_version = requests.__version__
    if not requests_version.startswith('2.2'):
        raise Exception()
except Exception:
    requests_version = '?'
    #NOTE: Fixed to support python3
    print("Warning: Your version of requests ({}) might not " \
            "be compatible with this module.".format(requests_version), file=sys.stderr)
    print("Officially supported are versions 2.2.x", file=sys.stderr)
    #print >> sys.stderr, "Warning: Your version of requests (%s) might not " \
    #                     "be compatible with this module." % requests_version
    #print >> sys.stderr, "Officially supported are versions 2.2.x"


# copied these values from Lastline utility code (llutils.api.error)
# to make them available to users of client code. please keep in sync!
ANALYSIS_API_FILE_NOT_AVAILABLE = 101
ANALYSIS_API_UNKNOWN_RESOURCE_TYPE = 102 # undocumented
ANALYSIS_API_UNKNOWN_ANALYSIS_TYPE = 103 # undocumented
ANALYSIS_API_INVALID_CREDENTIALS = 104
ANALYSIS_API_INVALID_UUID = 105
ANALYSIS_API_NO_RESULT_FOUND = 106
ANALYSIS_API_TEMPORARILY_UNAVAILABLE = 107
ANALYSIS_API_PERMISSION_DENIED = 108
ANALYSIS_API_FILE_TOO_LARGE = 109
ANALYSIS_API_INVALID_DOMAIN = 110 # undocumented
ANALYSIS_API_INVALID_BACKEND = 111 # undocumented
ANALYSIS_API_INVALID_D_METADATA = 112
ANALYSIS_API_INVALID_FILE_TYPE = 113
ANALYSIS_API_INVALID_ARTIFACT_UUID = 114
ANALYSIS_API_SUBMISSION_LIMIT_EXCEEDED = 115
ANALYSIS_API_INVALID_HASH_ALGORITHM = 116
ANALYSIS_API_INVALID_URL = 117
ANALYSIS_API_INVALID_REPORT_VERSION = 118
ANALYSIS_API_FILE_EXTRACTION_FAILED = 119
ANALYSIS_API_NO_IOC_EXTRACTABLE = 120
ANALYSIS_API_CHILD_TASK_CHAIN_TOO_DEEP = 121
ANALYSIS_API_AUTHENTICATION_REQUIRED = 122
ANALYSIS_API_DATA_NO_LONGER_AVAILABLE = 123
ANALYSIS_API_INVALID_PRIORITY = 124

# other consts
ANALYSIS_API_NO_REPORT_DETAILS = -1


class Error(Exception):
    """
    Base exception class for this module.
    """


class WaitResultTimeout(Error):
    """
    Waiting for results timed out.
    """
    def __init__(self, msg="Waiting for results timed out"):
        Error.__init__(self, msg)


class InvalidSubApiType(Error):
    """
    Exception for invalid sub API operations.

    The analysis API consists of a number of views (sub APIs):
    (only analysis for now)
    Operations involving parts other than these will
    raise this exceptions.
    """
    def __init__(self, sub_api_type):
        Error.__init__(self)
        self.sub_api_type = sub_api_type

    def __str__(self):
        return "Invalid sub API '%s', expecting one of (%s)" % (
                        self.sub_api_type,
                        ','.join(AnalysisClientBase.SUB_APIS))


class InvalidFormat(Error):
    """
    Invalid format requested.
    """
    def __init__(self, requested_format):
        Error.__init__(self)
        self.format = requested_format

    def __str__(self):
        return "Requested Invalid Format '%s', expecting one of (%s)" % (
                         self.format,
                         ','.join(AnalysisClientBase.FORMATS))


class CommunicationError(Error):
    """
    Contacting Malscape failed.
    """
    def __init__(self, msg=None, error=None):
        Error.__init__(self, msg or error or '')
        self.__error = error

    def internal_error(self):
        return self.__error


class FailedRequestError(CommunicationError):
    """
    Exception class to group communication errors returned
    on failed HTTP requests.
    """
    def __init__(self, msg=None, error=None, status_code=None):
        CommunicationError.__init__(self, msg, error)
        self.__status_code = status_code

    def status_code(self):
        return self.__status_code


class InvalidAnalysisAPIResponse(Error):
    """
    An AnalysisAPI response was not in the expected format
    """


class AnalysisAPIError(Error):
    """
    Analysis API returned an error.

    The `error_code` member of this exception
    is the :ref:`error code returned by the API<error_codes>`.
    """
    def __init__(self, msg, error_code):
        Error.__init__(self)
        self.msg = msg
        self.error_code = error_code

    def __str__(self):
        if self.error_code:
            return "Analysis API error (%s): %s" % (self.error_code, self.msg)
        return "Analysis API error: %s" % self.msg


class RequestError(AnalysisAPIError):
    """
    Exception class to group errors that are permanent request errors when
    following the Lastline Analyst API protocol. These errors indicate a problem
    with the request sent to the server - if you repeat the same request, you
    cannot expect a different error.

    This group excludes temporary errors, such as authentication problems.
    """


class SubmissionInvalidError(RequestError):
    """
    Exception class to group errors that are permanent submission errors. See
    `RequestError` for details.
    """


class FileNotAvailableError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_FILE_NOT_AVAILABLE):
        AnalysisAPIError.__init__(self, msg, error_code)


class InvalidCredentialsError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_CREDENTIALS):
        AnalysisAPIError.__init__(self, msg, error_code)


class InvalidUUIDError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_UUID):
        RequestError.__init__(self, msg, error_code)


class NoResultFoundError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_NO_RESULT_FOUND):
        AnalysisAPIError.__init__(self, msg, error_code)


class TemporarilyUnavailableError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_TEMPORARILY_UNAVAILABLE):
        AnalysisAPIError.__init__(self, msg, error_code)


class PermissionDeniedError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_PERMISSION_DENIED):
        AnalysisAPIError.__init__(self, msg, error_code)


class FileTooLargeError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_FILE_TOO_LARGE):
        SubmissionInvalidError.__init__(self, msg, error_code)


class InvalidFileTypeError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_FILE_TYPE):
        SubmissionInvalidError.__init__(self, msg, error_code)


class InvalidMetadataError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_D_METADATA):
        SubmissionInvalidError.__init__(self, msg, error_code)


class InvalidArtifactError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_ARTIFACT_UUID):
        RequestError.__init__(self, msg, error_code)


class SubmissionLimitExceededError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_SUBMISSION_LIMIT_EXCEEDED):
        AnalysisAPIError.__init__(self, msg, error_code)


class InvalidHashAlgorithmError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_HASH_ALGORITHM):
        RequestError.__init__(self, msg, error_code)


class InvalidURLError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_URL):
        SubmissionInvalidError.__init__(self, msg, error_code)


class InvalidReportVersionError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_REPORT_VERSION):
        RequestError.__init__(self, msg, error_code)


class FileExtractionFailedError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_FILE_EXTRACTION_FAILED):
        SubmissionInvalidError.__init__(self, msg, error_code)


class NoIOCExtractableError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_NO_IOC_EXTRACTABLE):
        RequestError.__init__(self, msg, error_code)


class DataNoLongerAvailable(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_DATA_NO_LONGER_AVAILABLE):
        RequestError.__init__(self, msg, error_code)


class InvalidPriority(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_PRIORITY):
        RequestError.__init__(self, msg, error_code)


class AuthenticationError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_AUTHENTICATION_REQUIRED):
        AnalysisAPIError.__init__(self, msg, error_code)

#NOTE: Fixed to support python3
#class NamedStringIO(StringIO.StringIO):
class NamedStringIO(StringIO):
    """
    A wrapper around StringIO to make it look more like a real file-stream.
    """
    def __init__(self, buf='', name=None):
        # Sanitize buf:
        # None value is transformed into 'None'
        if not buf:
            buf = ''
        StringIO.StringIO.__init__(self, buf)
        self._name = name

    @property
    def name(self):
        """
        Get the name of the BytesIO, might be None
        """
        return self._name


#################
# client
#################


__COMPLETED_TASK_FIELDS = [
    "task_uuid",
    "score"
]
CompletedTask = collections.namedtuple("CompletedTask", __COMPLETED_TASK_FIELDS)


def get_time():
    """
    trivial wrapper around time.time to make testing easier
    """
    return time.time()


def purge_none(d):
    """
    Purge None entries from a dictionary
    """
    for k in d.keys():
        if d[k] is None:
            del d[k]
    return d


def hash_stream(stream, algorithm):
    """
    Compute the hash of a file-like object

    :param stream: stream to hash
    :param algorithm: should be one of hashlib.algorithms
    """
    if hasattr(hashlib, "algorithms"):
        if algorithm not in hashlib.algorithms:
            raise NotImplementedError("Hash function '%s' is not available" %
                                      algorithm)

    try:
        m = hashlib.new(algorithm)
    except ValueError:
        #unsupported hash type
        raise NotImplementedError("Hash function '%s' is not available" %
                                  algorithm)

    while True:
        s = stream.read(4096)
        if not s:
            break
        m.update(s)
    return m.hexdigest()


def parse_datetime(d):
    """
    Parse a datetime as formatted in one of the following formats:

    date: %Y-%m-%d'
    datetime: '%Y-%m-%d %H:%M:%S'
    datetime with microseconds: '%Y-%m-%d %H:%M:%S.%f'

    Can also handle a datetime.date or datetime.datetime object,
    (or anything that has year, month and day attributes)
    and converts it to datetime.datetime
    """
    if hasattr(d, "year") and hasattr(d, "month") and hasattr(d, "day"):
        return datetime.datetime(d.year, d.month, d.day)

    try:
        return datetime.datetime.strptime(
            d, AnalysisClientBase.DATETIME_MSEC_FMT)
    except ValueError: pass

    try:
        return datetime.datetime.strptime(d, AnalysisClientBase.DATETIME_FMT)
    except ValueError: pass

    try:
        return datetime.datetime.strptime(d, AnalysisClientBase.DATE_FMT)
    except ValueError:
        raise ValueError("Date '%s' does not match format '%s'" % (
                         d, "%Y-%m-%d[ %H:%M:%S[.%f]]'"))


class TaskCompletion(object):
    """
    Helper class to get score for all completed tasks

    :param analysis_client: analysis_apiclient.AnalysisClientBase

    Sample usage:

    tc = TaskCompletion(my_analysis_client)
    for completed_task in tc.get_completed(start,end):
        print completed_task.task_uuid, completed_task.score

    """
    def __init__(self, analysis_client):
        self.__analysis_client = analysis_client

    def get_completed(self, after, before):
        """
        Return scores of tasks completed in the specified time range.

        This takes care of using the analysis API's pagination
        to make sure it gets all tasks.

        :param after: datetime.datetime
        :param before: datetime.datetime

        :yield: sequence of `CompletedTask`

        :raise: InvalidAnalysisAPIResponse if response
            does not have the format we expect
        """
        try:
            while True:
                result = self.__analysis_client.get_completed(
                    after=after,
                    before=before,
                    include_score=True)

                data = result["data"]
                tasks = data["tasks"]
                if tasks:
                    for task_uuid, score in tasks.iteritems():
                        yield CompletedTask(task_uuid=task_uuid, score=score)

                # NOTE: Even if no tasks have been returned, the API may still have returned us
                # the flag to query again (e.g., on a sliding window of time).
                try:
                    more = int(data["more_results_available"])
                except (KeyError, TypeError, ValueError):
                    # this flag was not in the initial API specs, so be a bit loose about parsing it
                    more = 0
                if not more:
                    break

                last_ts = parse_datetime(data["before"])
                if last_ts >= before:
                    break

                after = last_ts

        except (KeyError, ValueError, TypeError, AttributeError):
            # attributeError needed in case iteritems is missing (not a dict)
            # let's give it the trace of the original exception, so we know
            # what the specific problem is!
            #trace = sys.exc_info()[2]
            #raise InvalidAnalysisAPIResponse("Unable to parse response to get_completed()"), None, trace
            #NOTE: Fixed for python3 support
            raise InvalidAnalysisAPIResponse("Unable to parse response to get_completed()")


class SubmissionTracker(object):
    """
    Helper class to track the state of submissions until they're completed

    :param analysis_client: analysis_apiclient.AnalysisClientBase
    :param task_completion: analysis_apiclient.TaskCompletion or None
        If not provided, will create one from the analysis_client.
        Providing this parameter explicitly is mainly for testing.

     - `track_submission()` is used to add the submission to the list of tasks
        that we are keeping track of.
     - `get_completed()` is used to get the results of tracked submissions
        that have completed so far

    Invocations of the two methods can be interleaved to add new tasks to keep
    track of while others are still waiting to be completed.
    """
    def __init__(self, analysis_client, task_completion=None):
        self.__analysis_client = analysis_client
        if not task_completion:
            task_completion = TaskCompletion(analysis_client)
        self.__task_completion = task_completion
        # tasks we are currently tracking
        self.__tracked_uuids = set()
        # how far back in time we have to go for completion call
        self.__min_timestamp = None

    @property
    def min_timestamp(self):
        """
        Minimum timestamp from which next calls to get_completed call will start.

        It may be useful to access this property
        to serialize the state of the SubmissionTracker.

        :rtype: datetime.datetime
        """
        return self.__min_timestamp

    @property
    def num_tracked_uuids(self):
        return len(self.__tracked_uuids)

    def get_tracked_uuids(self):
        """
        Return the current tracked uuids

        It may be useful to access this property
        to serialize the state of the SubmissionTracker.

        :return: Sequence of task_uuids
        """
        return set(self.__tracked_uuids)

    def track_submission(self, task_uuid, submission_utc_timestamp):
        """
        Start keeping track of the specified submission

        :param task_uuid: UUID of submission to track
        :type task_uuid: str
        :param submission_utc_timestamp: Timestamp of the submission according to
            the API server. A correct API timestamp can be obtained by
            invoking `AnalysiClientBase.get_api_timestamp()`.
            Providing a timestamp before the actual submission timestamp
            will also work but may lead to less efficient use
            of the get_completed API.
        :type submission_utc_timestamp: datetime.datetime
        """
        self.__tracked_uuids.add(task_uuid)
        if self.__min_timestamp:
            self.__min_timestamp = min(
                self.__min_timestamp, submission_utc_timestamp)
        else:
            self.__min_timestamp = submission_utc_timestamp

    def get_completed(self):
        """
        Get results for tracked tasks that have completed so far

        Once a completed task is returned by this method,
        it will be removed from the set of tasks that are being tracked,
        so it will not be returned again by later calls to this method.

        :yield: sequence of `CompletedTask`

        :raise: InvalidAnalysisAPIResponse if response
            does not have the format we expect
        """
        if not self.__tracked_uuids:
            return

        # cannot be None as otherwise we'd have no tracked uuids
        assert self.__min_timestamp is not None, "SubmissionTracker has no min_timestamp!"
        after = self.__min_timestamp
        before = self.__analysis_client.get_api_utc_timestamp()

        for completed_task in self.__task_completion.get_completed(after, before):
            try:
                self.__tracked_uuids.remove(completed_task.task_uuid)
                yield completed_task
            except KeyError:
                # not a task we are tracking, so ignore it
                pass

        # we've examined all tasks up to this point, so move the starting time
        self.__min_timestamp = before


class MockSession(object):
    """
    This class acts as a drop-in replacement for the python-requests Session object in cases where
    the API server does not support sessions. This feature was added a while back, but we want to
    make sure that the latest client works with older versions of the API server

    NOTE: Since we don't use real sessions, we cannot do GET requests, as we would leak sensitive
    parameters in the URL. Thus, this class changes any GET into a POST.

    NOTE: This is not a drop-in replacement for `requests.Session`. It only implements those parts
    of the Session object's interface that we actually use in the `AnalysisAPIClient` class.
    """
    def __init__(self, credentials, logger=None):
        self.__credentials = credentials
        self.__requests_session = None
        self.__logger = logger

    def request(self, method, url, **kwargs):
        """
        Perform a request on this session - for more details, refer to `requests.Session.request()`
        """
        if self.__requests_session is None:
            self.__requests_session = requests.session()

        data = {}
        try:
            data = kwargs.pop('data')
        except KeyError:
            pass
        else:
            # just to be on the safe side if someone explicitly passed in None
            if data is None:
                data = {}

        # rewrite GET to POST: see class doc-string
        if method.upper() == 'GET':
            method = 'POST'
            try:
                params = kwargs.pop('params')
            except KeyError:
                pass  # no GET args to deal with
            else:
                if params:
                    data.update(params)
            if self.__logger:
                self.__logger.debug(
                    "Rewrote %s %s to POST, moved %d GET args", method, url,
                    len(params) if params else 0)

        # now embed the credentials if needed
        #NOTE: Fixed to support python3
        #for key, value in self.__credentials.iteritems():
        for key, value in self.__credentials.items():
            if key not in data:
                data[key] = value

        # now do the actual request
        return self.__requests_session.request(method, url, data=data, **kwargs)

    def close(self):
        """
        Tear down this session object - for more details, refer to `requests.Session.close()`
        """
        self.__requests_session.close()


class AnalysisClientBase(object):
    """
    A client for the Lastline analysis API.

    This is an abstract base class: concrete
    subclasses just need to implement the _api_request
    method to actually send the API request to the server.

    :param base_url: URL where the lastline analysis API is located. (required)
    :param logger: if provided, should be a python logging.Logger object
        or object with similar interface.
    """
    SUB_APIS = ('analysis', 'management', 'authentication')

    DATETIME_FMT = '%Y-%m-%d %H:%M:%S'
    DATETIME_MSEC_FMT = DATETIME_FMT + '.%f'
    DATE_FMT = '%Y-%m-%d'

    FORMATS = ["json", "xml", "pdf", "rtf"]

    REQUEST_PERFDATA = False

    ERRORS = {
        ANALYSIS_API_FILE_NOT_AVAILABLE: FileNotAvailableError,
        ANALYSIS_API_INVALID_CREDENTIALS: InvalidCredentialsError,
        ANALYSIS_API_INVALID_UUID: InvalidUUIDError,
        ANALYSIS_API_NO_RESULT_FOUND: NoResultFoundError,
        ANALYSIS_API_TEMPORARILY_UNAVAILABLE: TemporarilyUnavailableError,
        ANALYSIS_API_PERMISSION_DENIED: PermissionDeniedError,
        ANALYSIS_API_FILE_TOO_LARGE: FileTooLargeError,
        ANALYSIS_API_INVALID_FILE_TYPE: InvalidFileTypeError,
        ANALYSIS_API_INVALID_DOMAIN: InvalidMetadataError,
        ANALYSIS_API_INVALID_D_METADATA: InvalidMetadataError,
        ANALYSIS_API_INVALID_ARTIFACT_UUID: InvalidArtifactError,
        ANALYSIS_API_SUBMISSION_LIMIT_EXCEEDED: SubmissionLimitExceededError,
        ANALYSIS_API_INVALID_HASH_ALGORITHM: InvalidHashAlgorithmError,
        ANALYSIS_API_INVALID_URL: InvalidURLError,
        ANALYSIS_API_INVALID_REPORT_VERSION: InvalidReportVersionError,
        ANALYSIS_API_FILE_EXTRACTION_FAILED: FileExtractionFailedError,
        ANALYSIS_API_NO_IOC_EXTRACTABLE: NoIOCExtractableError,
        ANALYSIS_API_DATA_NO_LONGER_AVAILABLE: DataNoLongerAvailable,
        ANALYSIS_API_INVALID_PRIORITY: InvalidPriority,
        ANALYSIS_API_AUTHENTICATION_REQUIRED: AuthenticationError,
    }

    def __init__(self, base_url, logger=None, config=None):
        self.__logger = logger
        self.__base_url = base_url
        self.__config = config

    def _logger(self):
        return self.__logger

    def _build_url(self, sub_api, parts, requested_format="json"):
        if sub_api not in self.SUB_APIS:
            raise InvalidSubApiType(sub_api)
        if requested_format not in self.FORMATS:
            raise InvalidFormat(requested_format)
        num_parts = 2 + len(parts)
        pattern = "/".join(["%s"] * num_parts) + ".%s"
        params = [self.__base_url, sub_api] + parts + [requested_format]
        return pattern % tuple(params)

    def _build_file_download_url(self, sub_api, parts):
        """
        Generate a URL to a direct file download
        """
        if sub_api not in AnalysisClientBase.SUB_APIS:
            raise InvalidSubApiType(sub_api)
        num_parts = 2 + len(parts)
        pattern = "/".join(["%s"] * num_parts)
        params = [self.__base_url, sub_api] + parts
        return pattern % tuple(params)

    def _check_file_like(self, f, param_name):
        if not hasattr(f, 'read'):
            raise AttributeError("The %s parameter is not a file-like object" %
                                 param_name)

    def submit_exe_hash(self,
                        md5=None,
                        sha1=None,
                        download_ip=None,
                        download_port=None,
                        download_url=None,
                        download_host=None,
                        download_path=None,
                        download_agent=None,
                        download_referer=None,
                        download_request=None,
                        full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                        bypass_cache=None,
                        raw=False,
                        verify=True):
        """
        Submit a file by hash.

        *Deprecated*. Use `submit_file_hash()`
        """
        return self.submit_file_hash(md5, sha1,
                        download_ip=download_ip,
                        download_port=download_port,
                        download_url=download_url,
                        download_host=download_host,
                        download_path=download_path,
                        download_agent=download_agent,
                        download_referer=download_referer,
                        download_request=download_request,
                        full_report_score=full_report_score,
                        bypass_cache=bypass_cache,
                        raw=raw,
                        verify=verify)

    def submit_file_hash(self,
                        md5=None,
                        sha1=None,
                        sha256=None,
                        download_ip=None,
                        download_port=None,
                        download_url=None,
                        download_host=None,
                        download_path=None,
                        download_agent=None,
                        download_referer=None,
                        download_request=None,
                        full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                        bypass_cache=None,
                        password=None,
                        password_candidates=None,
                        backend=None,
                        require_file_analysis=True,
                        mime_type=None,
                        analysis_timeout=None,
                        analysis_env=None,
                        allow_network_traffic=None,
                        filename=None,
                        keep_file_dumps=None,
                        keep_memory_dumps=None,
                        keep_behavior_log=None,
                        push_to_portal_account=None,
                        raw=False,
                        verify=True,
                        server_ip=None,
                        server_port=None,
                        server_host=None,
                        client_ip=None,
                        client_port=None,
                        is_download=True,
                        protocol="http",
                        apk_package_name=None,
                        report_version=None,
                        analysis_task_uuid=None,
                        analysis_engine=None,
                        task_metadata=None,
                        priority=None,
                        bypass_prefilter=None):
        """
        Submit a file by hash.

        One of the md5, sha1, or sha256 parameters must be provided.
        If both are provided, they should be consistent.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.submit_file`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param md5: md5 hash of file.
        :param sha1: sha1 hash of file.
        :param sha256: sha256 hash of file.
        :param download_ip: DEPRECATED! Use server_ip instead.
        :param download_port: DEPRECATED! Use server_port instead.
        :param download_url: DEPRECATED! replaced by the download_host
            and download_path parameters
        :param download_host: hostname of the server-side endpoint of
            the connection, as a string of bytes (not unicode).
        :param download_path: host path from which the submitted file
            was originally downloaded, as a string of bytes (not unicode)
        :param download_agent: HTTP user-agent header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_referer: HTTP referer header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_request: full HTTP request with
            which the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param bypass_cache: if True, the API will not serve a cached
            result. NOTE: This requires special privileges.
        :param password: password used to analyze password-protected or
            encrypted content (such as archives or documents)
        :param password_candidates: List of passwords used to analyze password-protected or
            encrypted content (such as archives or documents)
        :param require_file_analysis: if True, the submission requires an
            analysis run to be started. If False, the API will attempt to
            base a decision solely on static information such as
            download source reputation and hash lookups. Requires special
            permissions; Lastline-internal/do not use
        :param mime_type: the mime-type of the file; This value should be
            set when require_file_analysis is True to enforce getting the
            most information available
        :param analysis_timeout: timeout in seconds after which to terminate
            analysis. The analysis engine might decide to extend this timeout
            if necessary. If all analysis subjects terminate before this timeout
            analysis might be shorter
        :param analysis_env: environment in which to run analysis. This includes
            the operating system as well as version of tools such as Microsoft
            Office. Example usage:
            - windows7:office2003, or
            - windowsxp
            By default, analysis will run on all available operating systems
            using the most applicable tools.
        :param allow_network_traffic: if False, all network connections will be
            redirected to a honeypot. Requires special permissions.
        :param filename: filename to use during analysis. If none is passed,
            the analysis engine will pick an appropriate name automatically.
            An easy way to pass this value is to use 'file_stream.name' for most
            file-like objects
        :param keep_file_dumps: if True, all files generated during
            analysis will be kept for post-processing. NOTE: This can generate
            large volumes of data and is not recommended. Requires special
            permissions
        :param keep_memory_dumps: if True, all buffers allocated during
            analysis will be kept for post-processing. NOTE: This can generate
            *very* large volumes of data and is not recommended. Requires
            special permissions
        :param keep_behavior_log: if True, the raw behavior log extracted during
            analysis will be kept for post-processing. NOTE: This can generate
            *very very* large volumes of data and is not recommended. Requires
            special permissions
        :param push_to_portal_account: if set, a successful submission will be
            pushed to the web-portal using the specified account
        :param backend: DEPRECATED! Don't use
        :param verify: if False, disable SSL-certificate verification
        :param raw: if True, return the raw json results of the API query
        :param server_ip: ASCII dotted-quad representation of the IP address of
            the server-side endpoint.
        :param server_port: integer representation of the port number
            of the server-side endpoint of the flow tuple.
        :param server_host: DEPRECATED! Don't use
        :param client_ip: ASCII dotted-quad representation of the IP address of
            the client-side endpoint.
        :param client_port: integer representation of the port number
            of the client-side endpoint of the flow tuple.
        :param is_download: Boolean; True if the transfer happened in the
            server -> client direction, False otherwise (client -> server).
        :param protocol: app-layer protocol in which the file got
            transferred. Short ASCII string.
        :param apk_package_name: package name for APK files. Don't specify
            manually.
        :param report_version: Version name of the Report that will be returned
                               (optional);
        :param analysis_task_uuid: if the call is used to create a child task,
            it specifies the current analysis task UUID; None otherwise.
            Lastline-internal/do not use.
        :param analysis_engine: if analysis_task_uuid is provided, it specifies
            the sandbox it refers to; None otherwise. Lastline-internal/do not
            use.
        :param task_metadata: optional task-metadata to upload. Requires special
            permissions; Lastline-internal/do not use
        :param priority: Priority level to set for this analysis. Priority should
            be between 1 and 10 (1 is the lowest priority, 10 is the highest).
            Setting priority to any value other than 1 requires special permissions.
        :param bypass_prefilter: Boolean; If True, file is submitted to all supported
            analysis components without prior static analysis. Requires special permissions.
        """
        # this parameter was introduced into the LLAPI-client at some point, but
        # it's actually not supported by the API!
        _unused = server_host

        if self.__logger and backend:
            self.__logger.warning("Ignoring deprecated parameter 'backend'")

        url = self._build_url("analysis", ["submit", "file"])
        # These options require special permissions, so we should not set them
        # if not specified
        if allow_network_traffic is not None:
            allow_network_traffic = allow_network_traffic and 1 or 0
        if keep_file_dumps is not None:
            keep_file_dumps = keep_file_dumps and 1 or 0
        if keep_memory_dumps is not None:
            keep_memory_dumps = keep_memory_dumps and 1 or 0
        if keep_behavior_log is not None:
            keep_behavior_log = keep_behavior_log and 1 or 0
        if bypass_prefilter is not None:
            bypass_prefilter = bypass_prefilter and 1 or 0
        params = purge_none({
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "full_report_score": full_report_score,
            "bypass_cache": bypass_cache and 1 or None,
            "password": password,
            "require_file_analysis": require_file_analysis and 1 or 0,
            "mime_type": mime_type,
            "download_ip": download_ip,
            "download_port": download_port,
            # analysis-specific options:
            "analysis_timeout": analysis_timeout or None,
            "analysis_env": analysis_env,
            "allow_network_traffic": allow_network_traffic,
            "filename": filename,
            "keep_file_dumps": keep_file_dumps,
            "keep_memory_dumps": keep_memory_dumps,
            "keep_behavior_log": keep_behavior_log,
            "push_to_portal_account": push_to_portal_account or None,
            "server_ip": server_ip,
            "server_port": server_port,
            "client_ip": client_ip,
            "client_port": client_port,
            "is_download": is_download,
            "protocol": protocol,
            "apk_package_name": apk_package_name,
            "report_version": report_version,
            "analysis_task_uuid": analysis_task_uuid,
            "analysis_engine": analysis_engine,
            "priority": priority,
            "bypass_prefilter": bypass_prefilter,
        })
        # using and-or-trick to convert to a StringIO if it is not None
        # this just wraps it into a file-like object
        files = purge_none({
            "download_url": download_url is not None and \
                               StringIO.StringIO(download_url) or None,
            "download_host": download_host is not None and \
                               StringIO.StringIO(download_host) or None,
            "download_path": download_path is not None and \
                               StringIO.StringIO(download_path) or None,
            "download_agent": download_agent is not None and \
                               StringIO.StringIO(download_agent) or None,
            "download_referer": download_referer is not None and \
                               StringIO.StringIO(download_referer) or None,
            "download_request": download_request is not None and \
                               StringIO.StringIO(download_request) or None,
            "task_metadata": StringIO.StringIO(simplejson.dumps(task_metadata))
                if task_metadata is not None else None,
            # NOTE: We enforce that the given collection is a unique list (set cannot be
            # serialized). Further, if we are given an empty collection, we don't bother sending
            # the json
            "password_candidates": StringIO.StringIO(simplejson.dumps(
                list(set(password_candidates)))) if password_candidates else None,
        })
        return self._api_request(url, params, files=files, post=True,
                                 raw=raw, verify=verify)

    def submit_exe_file(self,
                        file_stream,
                        download_ip=None,
                        download_port=None,
                        download_url=None,
                        download_host=None,
                        download_path=None,
                        download_agent=None,
                        download_referer=None,
                        download_request=None,
                        full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                        bypass_cache=None,
                        delete_after_analysis=False,
                        raw=False,
                        verify=True):
        """
        Submit a file by uploading it.

        *Deprecated*. Use `submit_file()`
        """
        return self.submit_file(file_stream,
                        download_ip=download_ip,
                        download_port=download_port,
                        download_url=download_url,
                        download_host=download_host,
                        download_path=download_path,
                        download_agent=download_agent,
                        download_referer=download_referer,
                        download_request=download_request,
                        full_report_score=full_report_score,
                        bypass_cache=bypass_cache,
                        delete_after_analysis=delete_after_analysis,
                        raw=raw,
                        verify=verify)

    def submit_file(self, file_stream,
                    download_ip=None,
                    download_port=None,
                    download_url=None,
                    download_host=None,
                    download_path=None,
                    download_agent=None,
                    download_referer=None,
                    download_request=None,
                    full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                    bypass_cache=None,
                    delete_after_analysis=None,
                    backend=None,
                    analysis_timeout=None,
                    analysis_env=None,
                    allow_network_traffic=None,
                    filename=None,
                    keep_file_dumps=None,
                    keep_memory_dumps=None,
                    keep_behavior_log=None,
                    push_to_portal_account=None,
                    raw=False,
                    verify=True,
                    server_ip=None,
                    server_port=None,
                    server_host=None,
                    client_ip=None,
                    client_port=None,
                    is_download=True,
                    protocol="http",
                    apk_package_name=None,
                    password=None,
                    password_candidates=None,
                    report_version=None,
                    analysis_task_uuid=None,
                    analysis_engine=None,
                    task_metadata=None,
                    priority=None,
                    bypass_prefilter=None):
        """
        Submit a file by uploading it.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.submit_file`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param file_stream: file-like object containing
            the file to upload.
        :param download_ip: DEPRECATED! Use server_ip instead.
        :param download_port: DEPRECATED! Use server_port instead.
        :param download_url: DEPRECATED! replaced by the download_host
            and download_path parameters
        :param download_host: hostname of the server-side endpoint of
            the connection, as a string of bytes (not unicode).
        :param download_path: host path from which the submitted file
            was originally downloaded, as a string of bytes (not unicode)
        :param download_agent: HTTP user-agent header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_referer: HTTP referer header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_request: full HTTP request with
            which the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param bypass_cache: if True, the API will not serve a cached
            result. NOTE: This requires special privileges.
        :param delete_after_analysis: if True, the backend will delete the
            file after analysis is done (and noone previously submitted
            this file with this flag set)
        :param analysis_timeout: timeout in seconds after which to terminate
            analysis. The analysis engine might decide to extend this timeout
            if necessary. If all analysis subjects terminate before this timeout
            analysis might be shorter
        :param analysis_env: environment in which to run analysis. This includes
            the operating system as well as version of tools such as Microsoft
            Office. Example usage:
            - windows7:office2003, or
            - windowsxp
            By default, analysis will run on all available operating systems
            using the most applicable tools.
        :param allow_network_traffic: if False, all network connections will be
            redirected to a honeypot. Requires special permissions.
        :param filename: filename to use during analysis. If none is passed,
            the analysis engine will pick an appropriate name automatically.
            An easy way to pass this value is to use 'file_stream.name' for most
            file-like objects
        :param keep_file_dumps: if True, all files generated during
            analysis will be kept for post-processing. NOTE: This can generate
            large volumes of data and is not recommended. Requires special
            permissions
        :param keep_memory_dumps: if True, all buffers allocated during
            analysis will be kept for post-processing. NOTE: This can generate
            large volumes of data and is not recommended. Requires special
            permissions
        :param keep_behavior_log: if True, the raw behavior log extracted during
            analysis will be kept for post-processing. NOTE: This can generate
            *very very* large volumes of data and is not recommended. Requires
            special permissions
        :param push_to_portal_account: if set, a successful submission will be
            pushed to the web-portal using the specified username
        :param backend: DEPRECATED! Don't use
        :param verify: if False, disable SSL-certificate verification
        :param raw: if True, return the raw JSON results of the API query
        :param server_ip: ASCII dotted-quad representation of the IP address of
            the server-side endpoint.
        :param server_port: integer representation of the port number
            of the server-side endpoint of the flow tuple.
        :param server_host: DEPRECATED! Don't use
        :param client_ip: ASCII dotted-quad representation of the IP address of
            the client-side endpoint.
        :param client_port: integer representation of the port number
            of the client-side endpoint of the flow tuple.
        :param is_download: Boolean; True if the transfer happened in the
            server -> client direction, False otherwise (client -> server).
        :param protocol: app-layer protocol in which the file got
            transferred. Short ASCII string.
        :param report_version: Version name of the Report that will be returned
                               (optional);
        :param apk_package_name: package name for APK files. Don't specify
            manually.
        :param password: password used to analyze password-protected or
                encrypted content (such as archives or documents)
        :param password_candidates: List of passwords used to analyze password-protected or
                encrypted content (such as archives or documents)
        :param analysis_task_uuid: if the call is used to create a child task,
            it specifies the current analysis task UUID; None otherwise.
            Lastline-internal/do not use.
        :param analysis_engine: if analysis_task_uuid is provided, it specifies
            the sandbox it refers to; None otherwise. Lastline-internal/do not
            use.
        :param task_metadata: optional task-metadata to upload. Requires special
            permissions; Lastline-internal/do not use
        :param priority: Priority level to set for this analysis. Priority should
            be between 1 and 10 (1 is the lowest priority, 10 is the highest)
            Setting priority to any value other than 1 requires special permissions.
        :param bypass_prefilter: Boolean; If True, file is submitted to all supported
            analysis components without prior static analysis. Requires special permissions.
        """
        # this parameter was introduced into the LLAPI-client at some point, but
        # it's actually not supported by the API!
        _unused = server_host

        if self.__logger and backend:
            self.__logger.warning("Ignoring deprecated parameter 'backend'")

        if filename is None and hasattr(file_stream, 'name'):
            filename = path.basename(file_stream.name)

        self._check_file_like(file_stream, "file_stream")
        url = self._build_url("analysis", ["submit", "file"])
        # These options require special permissions, so we should not set them
        # if not specified
        if allow_network_traffic is not None:
            allow_network_traffic = allow_network_traffic and 1 or 0
        if keep_file_dumps is not None:
            keep_file_dumps = keep_file_dumps and 1 or 0
        if keep_memory_dumps is not None:
            keep_memory_dumps = keep_memory_dumps and 1 or 0
        if keep_behavior_log is not None:
            keep_behavior_log = keep_behavior_log and 1 or 0
        if bypass_prefilter is not None:
            bypass_prefilter = bypass_prefilter and 1 or 0
        params = purge_none({
            "bypass_cache": bypass_cache and 1 or None,
            "full_report_score": full_report_score,
            "delete_after_analysis": delete_after_analysis and 1 or 0,
            "download_ip": download_ip,
            "download_port": download_port,
            # analysis-specific options:
            "analysis_timeout": analysis_timeout or None,
            "analysis_env": analysis_env,
            "allow_network_traffic": allow_network_traffic,
            "filename": filename,
            "keep_file_dumps": keep_file_dumps,
            "keep_memory_dumps": keep_memory_dumps,
            "keep_behavior_log": keep_behavior_log,
            "push_to_portal_account": push_to_portal_account or None,
            "server_ip": server_ip,
            "server_port": server_port,
            "client_ip": client_ip,
            "client_port": client_port,
            "is_download": is_download,
            "protocol": protocol,
            "apk_package_name": apk_package_name,
            "password": password,
            "report_version": report_version,
            "analysis_task_uuid": analysis_task_uuid,
            "analysis_engine": analysis_engine,
            "priority": priority,
            "bypass_prefilter": bypass_prefilter,
        })

        # using and-or-trick to convert to a StringIO if it is not None
        # this just wraps it into a file-like object
        files = purge_none({
            # If an explicit filename was provided, we can pass it down to
            # python-requests to use it in the multipart/form-data. This avoids
            # having python-requests trying to guess the filenam based on stream
            # attributes.
            #
            # The problem with this is that, if the filename is not ASCII, then
            # this triggers a bug in flask/werkzeug which means the file is
            # thrown away. Thus, we just force an ASCII name
            "file": ('dummy-ascii-name-for-file-param', file_stream),
            "download_url": download_url is not None and \
                                  StringIO.StringIO(download_url) or None,
            "download_host": download_host is not None and \
                                  StringIO.StringIO(download_host) or None,
            "download_path": download_path is not None and \
                                  StringIO.StringIO(download_path) or None,
            "download_agent": download_agent is not None and \
                                  StringIO.StringIO(download_agent) or None,
            "download_referer": download_referer is not None and \
                                  StringIO.StringIO(download_referer) or None,
            "download_request": download_request is not None and \
                                  StringIO.StringIO(download_request) or None,
            "task_metadata": StringIO.StringIO(simplejson.dumps(task_metadata))
                if task_metadata is not None else None,
            # NOTE: We enforce that the given collection is a unique list (set cannot be
            # serialized). Further, if we are given an empty collection, we don't bother sending
            # the json
            "password_candidates": StringIO.StringIO(simplejson.dumps(
                list(set(password_candidates)))) if password_candidates else None,
        })
        return self._api_request(url, params, files=files, post=True,
                                 raw=raw, verify=verify)


    def submit_file_metadata(self, md5, sha1,
                                   download_ip,
                                   download_port,
                                   download_host=None,
                                   download_path=None,
                                   download_agent=None,
                                   download_referer=None,
                                   download_request=None,
                                   raw=False,
                                   verify=True):
        """
        Submit metadata regarding a file download.

        *Deprecated*. Do not use.

        Both the md5 and the sha1 parameter must be provided.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param md5: md5 hash of the downloaded file.
        :param sha1: sha1 hash of the downloaded file.
        :param download_ip: ASCII dotted-quad representation of the IP address
            from which the file has been downloaded
        :param download_port: integer representation of the port number
            from which the file has been downloaded
        :param download_host: host from which the submitted file
            was originally downloaded, as a string of bytes (not unicode)
        :param download_path: host path from which the submitted file
            was originally downloaded, as a string of bytes (not unicode)
        :param download_agent: HTTP user-agent header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_referer: HTTP referer header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_request: full HTTP request with
            which the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param verify: if False, disable SSL-certificate verification
        :param raw: if True, return the raw json results of the API query
        """
        url = self._build_url("analysis", ["submit", "download"])
        params = {
            "md5": md5,
            "sha1": sha1,
            "download_ip": download_ip,
            "download_port": download_port
        }
        #using and-or-trick to convert to a StringIO if it is not None
        #this just wraps it into a file-like object
        files = {
            "download_host": download_host is not None and \
                                   StringIO.StringIO(download_host) or None,
            "download_path": download_path is not None and \
                                   StringIO.StringIO(download_path) or None,
            "download_agent": download_agent is not None and \
                                   StringIO.StringIO(download_agent) or None,
            "download_referer": download_referer is not None and \
                                   StringIO.StringIO(download_referer) or None,
            "download_request": download_request is not None and \
                                   StringIO.StringIO(download_request) or None

        }
        purge_none(files)
        purge_none(params)
        return self._api_request(url, params, files=files, post=True,
                                 raw=raw, verify=verify)


    def submit_url(self,
                   url,
                   referer=None,
                   full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                   bypass_cache=None,
                   backend=None,
                   analysis_timeout=None,
                   push_to_portal_account=None,
                   raw=False,
                   verify=True,
                   user_agent=None,
                   report_version=None,
                   analysis_task_uuid=None,
                   analysis_engine=None,
                   priority=None):
        """
        Submit a url.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.submit_url`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param url: url to analyze
        :param referer: referer header to use for analysis
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param bypass_cache: if True, the API will not serve a cached
            result. NOTE: This requires special privileges.
        :param analysis_timeout: timeout in seconds after which to terminate
            analysis. The analysis engine might decide to extend this timeout
            if necessary. If all analysis subjects terminate before this timeout
            analysis might be shorter
        :param push_to_portal_account: if set, a successful submission will be
            pushed to the web-portal using the specified account
        :param backend: DEPRECATED! Don't use
        :param verify: if False, disable SSL-certificate verification
        :param raw: if True, return the raw JSON results of the API query
        :param report_version: Version name of the Report that will be returned
                               (optional);
        :param user_agent: user agent header to use for analysis
        :param analysis_task_uuid: if the call is used to create a child task,
            it specifies the current analysis task UUID; None otherwise.
            Lastline-internal/do not use.
        :param analysis_engine: if analysis_task_uuid is provided, it specifies
            the sandbox it refers to; None otherwise. Lastline-internal/do not
            use.
        :param priority: Priority level to set for this analysis. Priority should
            be between 1 and 10 (1 is the lowest priority, 10 is the highest).
            Setting priority to any value other than 1 requires special permissions.
        """
        if self.__logger and backend:
            self.__logger.warning("Ignoring deprecated parameter 'backend'")

        api_url = self._build_url("analysis", ["submit", "url"])
        params = purge_none({
            "url":url,
            "referer":referer,
            "full_report_score":full_report_score,
            "bypass_cache":bypass_cache and 1 or None,
            "analysis_timeout": analysis_timeout or None,
            "push_to_portal_account": push_to_portal_account or None,
            "user_agent": user_agent or None,
            "report_version": report_version,
            "analysis_task_uuid": analysis_task_uuid or None,
            "analysis_engine": analysis_engine,
            "priority": priority,
        })
        return self._api_request(api_url, params, post=True,
                                 raw=raw, verify=verify)

    def get_result(self,
                   uuid,
                   report_uuid=None,
                   full_report_score=None,
                   include_scoring_components=None,
                   raw=False,
                   requested_format="json",
                   verify=True,
                   report_version=None):
        """
        Get results for a previously submitted analysis task.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_results`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param report_uuid: if set, include this report in the result.
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param include_scoring_components: if True, the result will contain
            details of all components contributing to the overall score.
            Requires special permissions
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON, XML, PDF, or RTF.
            If format is not JSON, this implies `raw`.
        :param report_version: Version of the report to be returned
                               (optional)
        """
        # better: use 'get_results()' but that would break
        # backwards-compatibility
        url = self._build_url('analysis', ['get'],
                               requested_format=requested_format)
        params = purge_none({
            'uuid': uuid,
            'report_uuid': report_uuid,
            'full_report_score': full_report_score,
            'include_scoring_components': include_scoring_components and 1 or 0,
            'report_version': report_version
        })
        if requested_format.lower() != 'json':
            raw = True
        # NOTE: This API request may return real HTTP status-codes (and errors)
        # directly when fetching IOC reports.
        try:
            result = self._api_request(url,
                                       params,
                                       raw=raw,
                                       requested_format=requested_format,
                                       verify=verify)
        #NOTE: Fixed for python3 support
        #except FailedRequestError, exc: 
        except (FailedRequestError) as exc:
            status_code = str(exc.status_code())

            if status_code == '404':
                raise InvalidUUIDError(str(exc))

            if status_code == '412':
                raise NoResultFoundError(str(exc))

            # we have nothing more specific to say -- raise the
            # original FailedRequestError
            raise

        # Legacy support:
        # results are always returned as strings no matter
        # the content disposition of the server response.
        if isinstance(result, NamedStringIO):
            return result.read()

        return result

    def get_result_summary(self, uuid, raw=False,
                           requested_format="json",
                           score_only=False,
                           verify=True):
        """
        Get result summary for a previously submitted analysis task.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_result`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this
            implies `raw`.
        :param score_only: if True, return even less data (only score and
            threat/threat-class classification).
        """
        url = self._build_url("analysis", ["get_result"],
                               requested_format=requested_format)
        params = {
            'uuid': uuid,
            'score_only': score_only and 1 or 0,
        }
        if requested_format.lower() != "json":
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def get_result_activities(self, uuid, raw=False,
                              requested_format="json",
                              verify=True):
        """
        Get the behavior/activity information for a previously submitted
        analysis task.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_result_activities`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this
            implies `raw`.
        """
        url = self._build_url("analysis", ["get_result_activities"],
                               requested_format=requested_format)
        params = { 'uuid': uuid }
        if requested_format.lower() != "json":
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def get_report_activities(self, uuid, report_uuid, raw=False,
                              requested_format="json",
                              verify=True):
        """
        Get the behavior/activity information for a specific analysis report.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_report_activities`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param report_uuid: the unique report identifier returned as part of
            the dictionary returned by get_result().
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this
            implies `raw`.
        """
        url = self._build_url("analysis", ["get_report_activities"],
                               requested_format=requested_format)
        params = {
            'uuid': uuid,
            'report_uuid': report_uuid,
        }
        if requested_format.lower() != "json":
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def get_result_artifact(self, uuid, report_uuid, artifact_name,
                            raw=False, verify=True):
        """
        Get artifact generated by an analysis result for a previously
        submitted analysis task.

        NOTE: Consider using `get_report_artifact()` if the artifact is bound to a specific
        analysis report (which it is in practically all cases.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param report_uuid: the unique report identifier returned as part of
            the dictionary returned by get_result().
        :param artifact_name: the name of the artifact as mentioned in the
            given report in the dictionary returned by get_result().
        :param raw: if True, return the raw JSON/XML results of the API query.
        """
        # NOTE: we cannot simply use "get_report_artifact" in this function, because that
        # function does not allow returning JSON/XML formatted data
        url = self._build_file_download_url("analysis",
                                             ["get_result_artifact"])
        params = {
            'uuid': uuid,
            'artifact_uuid': "%s:%s" % (report_uuid, artifact_name)
        }

        # NOTE: This API request is completely different because it
        # returns real HTTP status-codes (and errors) directly
        try:
            result = self._api_request(url, params, requested_format='raw',
                                       raw=raw, verify=verify)
            if not result.len:
                raise InvalidArtifactError("The artifact is empty")
        
        #NOTE: Fixed for python3 support
        #except FailedRequestError, exc:
        except (FailedRequestError) as exc:
            status_code = str(exc.status_code())

            if status_code == '401':
                raise PermissionDeniedError(
                    "Permission denied to access artifacts")

            if status_code == '404':
                raise InvalidArtifactError(str(exc))

            if status_code == '410':
                raise InvalidArtifactError(
                    "The artifact is no longer available")

            if status_code == '412':
                raise InvalidUUIDError(str(exc))

            # we have nothing more specific to say -- raise the
            # original FailedRequestError
            raise

        if not result.len:
            raise InvalidArtifactError("The artifact is empty")
        return result

    def get_report_artifact(self, uuid, report_uuid, artifact_name, verify=True):
        """
        Get artifact generated by an analysis result for a previously
        submitted analysis task.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :type uuid: `str`
        :param report_uuid: the unique report identifier returned as part of
            the dictionary returned by get_result().
        :type report_uuid: `str`
        :param artifact_name: the name of the artifact as mentioned in the
            given report in the dictionary returned by get_result().
        :type artifact_name: `str`
        :returns: A stream containing the artifact content
        :rtype: stream
        :raises RequestError: Invalid parameters provided (e.g., unkown uuid)
        :raises FailedRequestError: Talking to the API failed
        :raises InvalidArtifactError: The artifact is no longer/not available
        """
        url = self._build_file_download_url("analysis", ["get_report_artifact"])
        params = {
            'uuid': uuid,
            'report_uuid': report_uuid,
            'artifact_name': artifact_name,
        }

        # NOTE: This API request is completely different because it
        # returns real HTTP status-codes (and errors) directly
        try:
            result = self._api_request(
                url,
                params,
                requested_format='raw',
                raw=True,
                verify=verify)
        except FailedRequestError as exc:
            status_code = str(exc.status_code())
            if status_code == '401':
                raise PermissionDeniedError("Permission denied to access artifacts")
            if status_code == '404':
                raise InvalidArtifactError(str(exc))
            if status_code == '410':
                raise InvalidArtifactError("The artifact is no longer available")
            if status_code == '412':
                raise InvalidUUIDError(str(exc))
            # we have nothing more specific to say -- raise the
            # original FailedRequestError
            raise

        return result

    def query_task_artifact(self, uuid, artifact_name, raw=False, verify=True):
        """
        Query if a specific task artifact is available for download.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param artifact_name: the name of the artifact
        :param raw: if True, return the raw JSON/XML results of the API query.
        """
        url = self._build_url("analysis", ["query_task_artifact"])
        params = purge_none({
            'uuid': uuid,
            'artifact_name': artifact_name,
        })
        return self._api_request(url, params, raw=raw, verify=verify)

    def get_ioc_metadata(self, ioc_uuid,
                         raw=False,
                         requested_format="json",
                         verify=True):
        """
        Get metadata about a previously generated IOC report by its UUID.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_ioc_metadata`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param ioc_uuid: the unique identifier of the IOC, as returned by
            `get_results()`.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML.
            If format is not JSON, this implies `raw`.
        """
        url = self._build_url('analysis', ['ioc', 'get_ioc_metadata'],
                               requested_format=requested_format)
        params = { 'ioc_uuid': ioc_uuid }
        if requested_format.lower() != 'json':
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def get_ioc_report(self, ioc_uuid,
                       raw=False,
                       requested_format="json",
                       verify=True):
        """
        Get an IOC report by its UUID.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_ioc_report`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param ioc_uuid: the unique identifier of the IOC, as returned by
            `get_results()`.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML.
            If format is not JSON, this implies `raw`.
        """
        url = self._build_url('analysis', ['ioc', 'get_ioc_report'],
                               requested_format=requested_format)
        params = { 'ioc_uuid': ioc_uuid }
        if requested_format.lower() != 'json':
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def create_ioc_from_result(self,
                               uuid,
                               report_uuid=None,
                               raw=False,
                               requested_format="json",
                               verify=True,
                               report_version=None):
        """
        Get an IOC report by its UUID.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.create_ioc_from_result`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param uuid: the unique identifier of the task,
            as returned in the task_uuid field of submit methods.
        :param report_uuid: report from which to generated an IOC.
        :param requested_format: JSON, XML, or RAW.
            If format is not JSON, this implies `raw`.
        :param report_version: IOC format.
        """
        url = self._build_url('analysis', ['ioc', 'create_ioc_from_result'],
                               requested_format=requested_format)
        params = purge_none({
            'uuid': uuid,
            'report_uuid': report_uuid,
            'report_version': report_version,
        })
        if requested_format.lower() != 'json':
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 post=True,
                                 verify=verify)

    def completed(self, after, before=None, raw=False, verify=True):
        """
        *Deprecated*. Use 'get_completed()'
        """
        return self.get_completed(after, before=before,
                                  verify=verify, raw=raw)

    def get_completed(self, after, before=None, raw=False, verify=True,
                      include_score=False):
        """
        Get the list of uuids of tasks that were completed
        within a given time frame.

        The main use-case for this method is to periodically
        request a list of uuids completed since the last
        time this method was invoked, and then fetch
        each result with `get_results()`.

        Date parameters to this method can be:
         - date string: %Y-%m-%d'
         - datetime string: '%Y-%m-%d %H:%M:%S'
         - datetime.datetime object

        All times are in UTC.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_completed`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param after: Request tasks completed after this time.
        :param before: Request tasks completed before this time.
        :param include_score: If True, the response contains scores together
            with the task-UUIDs that have completed
        :param raw: if True, return the raw JSON results of the API query.
        """
        # better: use 'get_completed()' but that would break
        # backwards-compatibility
        url = self._build_url("analysis", ["completed"])
        if hasattr(before, "strftime"):
            before = before.strftime(AnalysisClientBase.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(AnalysisClientBase.DATETIME_FMT)
        params = purge_none({
            'before': before,
            'after': after,
            'include_score': include_score and 1 or 0,
        })
        return self._api_request(url, params, raw=raw, verify=verify)

    def get_pending(self, after=None, before=None, raw=False, verify=True):
        """
        Get the list of uuids of tasks that are pending (ie: not completed) within a given
        time frame.

        The main use-case for this method is for stateless clients to perform actions on
        pending tasks.

        Date parameters to this method can be:
         - date string: %Y-%m-%d'
         - datetime string: '%Y-%m-%d %H:%M:%S'
         - datetime.datetime object

        All times are in UTC.

        For return values and error codes please see
        :py:meth:`malscape.api.views.analysis.get_pending`.

        If there is an error and `raw` is not set, a
        :py:class:`AnalysisAPIError` exception will be raised.

        :param after: Request tasks completed after this time.
        :type after: `str` or `datetime.datetime`
        :param before: Request tasks completed before this time.
        :type before: `str` or `datetime.datetime`
        :param raw: if True, return the raw JSON results of the API query.
        :type raw: `bool`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        """
        url = self._build_url("analysis", ["get_pending"])
        if hasattr(before, "strftime"):
            before = before.strftime(AnalysisClientBase.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(AnalysisClientBase.DATETIME_FMT)
        params = purge_none({'before': before, 'after': after})
        return self._api_request(url, params, raw=raw, verify=verify)

    def get_progress(self, uuid, raw=False):
        """
        Get a progress estimate for a previously submitted analysis task.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_results`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        """
        url = self._build_url('analysis', ['get_progress'])
        params = { 'uuid': uuid }
        return self._api_request(url, params, raw=raw, post=True)

    def get_task_metadata(self, uuid, raw=False):
        """
        Get information about a task by its UUID.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.get_task_metadata`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        """
        url = self._build_url('analysis', ['get_task_metadata'])
        params = { 'uuid': uuid }
        return self._api_request(url, params, raw=raw)

    def query_file_hash(self, hash_value=None, algorithm=None, block_size=None,
                        md5=None, sha1=None, sha256=None, mmh3=None, raw=False):
        """
        Search for existing analysis results with the given file-hash.

        :param hash_value: The (partial) file-hash.
        :param algorithm: One of MD5/SHA1/SHA256/MMH3
        :param block_size: Size of the block (at file start) used for generating
            the hash-value. By default (or if 0), the entire file is assumed.
        :param md5: Helper to quickly set `hash_value` and `algorithm`
        :param sha1: Helper to quickly set `hash_value` and `algorithm`
        :param sha256: Helper to quickly set `hash_value` and `algorithm`
        :param mmh3: Helper to quickly set `hash_value` and `algorithm`
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this
            implies `raw`.
        """
        if md5 or sha1 or sha256 or mmh3:
            if hash_value or algorithm:
                raise TypeError("Conflicting values passed for hash/algorithm")
            if md5 and not sha1 and not sha256 and not mmh3:
                hash_value = md5
                algorithm = 'md5'
            elif sha1 and not md5 and not sha256 and not mmh3:
                hash_value = sha1
                algorithm = 'sha1'
            elif sha256 and not md5 and not sha1 and not mmh3:
                hash_value = sha256
                algorithm = 'sha256'
            elif mmh3 and not md5 and not sha1 and not sha256:
                hash_value = mmh3
                algorithm = 'mmh3'
            else:
                raise TypeError("Conflicting values passed for hash/algorithm")
        elif not hash_value or not algorithm:
            raise TypeError("Missing values for hash_value/algorithm")

        url = self._build_url('analysis', ['query/file_hash'])
        params = purge_none({
            'hash_value': hash_value,
            'hash_algorithm': algorithm,
            'hash_block_size': block_size,
        })
        return self._api_request(url, params, raw=raw)

    def is_blocked_file_hash(self, hash_value=None, algorithm=None,
                             block_size=None, md5=None, sha1=None, sha256=None,
                             mmh3=None, raw=False):
        """
        Check if the given file-hash belongs to a malicious file and we have
        gathered enough information to block based on this (partial) hash.

        :param hash_value: The (partial) file-hash.
        :param algorithm: One of MD5/SHA1/SHA256/MMH3
        :param block_size: Size of the block (at file start) used for generating
            the hash-value. By default (or if 0), the entire file is assumed.
        :param md5: Helper to quickly set `hash_value` and `algorithm`
        :param sha1: Helper to quickly set `hash_value` and `algorithm`
        :param sha256: Helper to quickly set `hash_value` and `algorithm`
        :param mmh3: Helper to quickly set `hash_value` and `algorithm`
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        """
        if md5 or sha1 or mmh3:
            if hash_value or algorithm:
                raise TypeError("Conflicting values passed for hash/algorithm")
            if md5 and not sha1 and not sha256 and not mmh3:
                hash_value = md5
                algorithm = 'md5'
            elif sha1 and not md5 and not sha256 and not mmh3:
                hash_value = sha1
                algorithm = 'sha1'
            elif sha256 and not md5 and not sha1 and not mmh3:
                hash_value = sha256
                algorithm = 'sha256'
            elif mmh3 and not md5 and not sha1 and not sha256:
                hash_value = mmh3
                algorithm = 'mmh3'
            else:
                raise TypeError("Conflicting values passed for hash/algorithm")
        elif not hash_value or not algorithm:
            raise TypeError("Missing values for hash_value/algorithm")

        url = self._build_url('analysis', ['query/is_blocked_file_hash'])
        params = purge_none({
            'hash_value': hash_value,
            'hash_algorithm': algorithm,
            'hash_block_size': block_size,
        })
        return self._api_request(url, params, raw=raw)

    def query_analysis_engine_tasks(self, analysis_engine_task_uuids,
                                    analysis_engine='analyst', raw=False):
        """
        Provide a set of task UUIDs from an analysis engine (such as Analyst
        Scheduler or Anubis) and find completed tasks that contain this analysis
        engine task.

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.query_analysis_engine_tasks`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        :param analysis_engine_task_uuids: List of analysis engine task UUIDs to
            search.
        :param analysis_engine: The analysis engine the task refers to.
        :param raw: if True, return the raw JSON results of the API query.
        """
        url = self._build_url('analysis', ['query/analysis_engine_tasks'])
        params = purge_none({
            'analysis_engine_task_uuids': ','.join(analysis_engine_task_uuids),
            'analysis_engine': analysis_engine,
        })
        return self._api_request(url, params, raw=raw)

    def analyze_sandbox_result(self, analysis_task_uuid,
                               analysis_engine='anubis',
                               full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                               bypass_cache=False,
                               raw=False):
        """
        Provide a task UUID from an analysis engine (such as Analyst Scheduler
        or Anubis) and trigger scoring of the activity captured by the analysis
        report.

        Similar to submitting by exe hash (md5/sha1/sha256) but we can enforce
        the precise analysis result (if there are multiple) that we want
        to score

        For return values and error codes please
        see :py:meth:`malscape.api.views.analysis.analyze_sandbox_result`.

        If there is an error and `raw` is not set,
        a :py:class:`AnalysisAPIError` exception will be raised.

        Requires specific permissions.

        :param analysis_task_uuid: The sandbox task UUID to analyze/import.
                                   Lastline-internal/do not use.
        :param analysis_engine: The sandbox the task refers to.
                                Lastline-internal/do not use.
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param bypass_cache: if True, the API will not serve a cached
            result. NOTE: This requires special privileges.
        :param raw: if True, return the raw JSON results of the API query.
        """
        url = self._build_url('analysis', ['analyze_sandbox_result'])
        params = {
            'analysis_task_uuid':analysis_task_uuid,
            'analysis_engine': analysis_engine,
            'full_report_score': full_report_score,
            'bypass_cache': bypass_cache and 1 or None,
        }
        purge_none(params)
        return self._api_request(url, params, raw=raw)

    def register_completion(self, uuid, force_register=True, raw=False):
        """
        Register submission of a given task_uuid to the user that is authenticated

        :param uuid: the unique identifier of the submitted task, as returned in the task_uuid
            field of submit methods.
        :type uuid: `str`
        :param force_register: If set to True indicate that we should create a submission even if
            we already have one in place for the same license/task-uuid. If False, don't create a
            new one unless needed
        :type force_register: `bool`
        :returns: Dictionary with information regarding if registered task is already completed
            or not
        :rtype: `dict`
        """
        url = self._build_url("analysis", ["register_completion"])
        params = purge_none({
            'uuid': uuid,
            'force_register': force_register and 1 or 0,
        })
        return self._api_request(url, params, post=True, raw=raw)

    def get_analysis_tags(self, uuid, raw=False, verify=True):
        """
        Get the analysis tags for an analysis task.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :type uuid: `str`
        :param raw: if True, return the raw JSON results of the API query.
        :type raw: `bool`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :return: Dictionary of analysis tag data
        :rtype `dict`
        """
        url = self._build_url("analysis", ["get_analysis_tags"])
        params = {
            'uuid': uuid,
        }
        return self._api_request(url, params, raw=raw, verify=verify)

    def _api_request(self,
                     url,
                     params=None,
                     files=None,
                     timeout=None,
                     post=False,
                     raw=False,
                     requested_format="json",
                     verify=True):
        """
        Send an API request and return the results.

        :param url: API URL to fetch.
        :param params: GET or POST parameters.
        :param files: files to upload with request.
        :param timeout: request timeout in seconds.
        :param post: use HTTP POST instead of GET
        :param raw: return the raw json results of API query
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        :param verify: if True, verify ssl, otherwise False
        """
        raise NotImplementedError("%s does not implement api_request()" % self.__class__.__name__)

    def _process_response_page(self, page, raw, requested_format, disposition=None):
        """
        Helper for formatting/processing api response before returning it.
        """
        if raw or requested_format.lower() != "json":

            # Handle special dispositions
            if disposition:
                disp_type = disposition.get('type')
                disp_params = disposition.get('params')

                if disp_type == 'attachment':
                    return NamedStringIO(
                        page, name=disp_params.get('filename'))

            return page

        #why does pylint think result is a bool??
        #pylint: disable=E1103
        result = simplejson.loads(page)
        success = result['success']
        if success:
            return result
        else:
            error_code = result.get('error_code', None)
            # raise the most specific error we can
            exception_class = AnalysisClientBase.ERRORS.get(error_code) or \
                              AnalysisAPIError
            raise exception_class(result['error'], error_code)

    def rescore_task(self, uuid=None, md5=None, sha1=None,
                     min_score=0, max_score=100,
                     threat=None, threat_class=None,
                     force_local=False, raw=False):
        """
        Enforce re-scoring of a specific task or multiple tasks based on the
        submitted file. Requires specific permissions.

        At least one of uuid/md5 must be provided. If sha1 is given, it must
        match with the md5 that was provided. Existing manual-score threat/
        threat-class information will not be overwritten unless an empty-
        string ('') is passed to this function.

        This API-call returns the task-UUIDs that were triggered for rescoring.

        NOTE: Even when a single task-UUID is passed, the API might decide to
        re-score all tasks for the same file!

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param md5: the md5 hash of the submitted file.
        :param sha1: the sha1 hash of the submitted file.
        :param force_local: if True, enforce that the manual score is applied
            only locally. This is the default for on-premise instances and
            cannot be enforced there. Requires special permissions.
        :param raw: if True, return the raw JSON/XML results of the API query.
        """
        assert uuid or md5, "Please provide task-uuid/md5"
        url = self._build_url('management', ['rescore'])
        params = purge_none({
            'uuid': uuid,
            'md5': md5,
            'sha1': sha1,
            'min_score': min_score,
            'max_score': max_score,
            'threat': threat,
            'threat_class': threat_class,
            # use the default if no force is set
            'force_local': force_local and 1 or None,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def rescore_scanner(self, scanner, after, before,
                         min_score=0, max_score=100,
                         min_scanner_score=0, max_scanner_score=100,
                         min_version=0, max_version=None,
                         test_flag=None, force=False,
                         raw=False):
        """
        Find tasks that triggered a certain scanner and mark them for
        reprocessing.

        This API-call returns the task-UUIDs that were triggered for rescoring.

        :param scanner: Name of the scanner.
        :param after: Reprocess tasks completed after this time.
        :param before: Reprocess tasks completed before this time.
        :param min_score: Minimum score of tasks to reprocess.
        :param max_score: Maximum score of tasks to reprocess.
        :param min_scanner_score: Minimum score of scanner detection (on backend
            task) to reprocess.
        :param max_scanner_score: Maximum score of scanner detection (on backend
            task) to reprocess.
        :param min_version: Minimum version of scanner to reprocess.
        :param max_version: Maximum version of scanner to reprocess.
        :param test_flag: If True, only affect backend-tasks where the scanner
            was in *test* mode; if False, only affect backend-tasks where the
            scanner was in *real* mode; otherwise affect all backend-tasks
            regardless of the *test* flag.
        :param force: By default, the API will refuse rescoring any scanners that
            affect more than 100 tasks. To rescore large amounts, distribute the
            work over multiple time-windows. This safety can be disabled by
            setting the *force* parameter to True.
        """
        if hasattr(before, "strftime"):
            before = before.strftime(AnalysisClientBase.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(AnalysisClientBase.DATETIME_FMT)

        url = self._build_url('management', ['rescore_scanner'])
        params = purge_none({
            'scanner': scanner,
            'after': after,
            'before': before,
            'min_score': min_score,
            'max_score': max_score,
            'min_scanner_score': min_scanner_score,
            'max_scanner_score': max_scanner_score,
            'min_version': min_version,
            'max_version': max_version,
        })
        if test_flag is not None:
            params['test_flag'] = test_flag and 1 or 0
        if force:
            params['force'] = 1
        return self._api_request(url, params, raw=raw, post=True)

    def suppress_scanner(self, scanner, max_version, raw=False):
        """
        Mark a scanner as suppressed.

        :param scanner: Name of the scanner.
        :param max_version: Version of scanner up to which it is supposed to be
            suppressed. So, if the first scanner-version that should be used
            for scoring is X, provide (X-1).
        """
        url = self._build_url('management', ['suppress_scanner'])
        params = purge_none({
            'scanner': scanner,
            'max_version': max_version,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def create_ticket(self, uuid=None, md5=None, sha1=None,
                      min_score=0, max_score=100, summary=None, labels=None,
                      is_false_negative=False, is_false_positive=False,
                      is_from_customer=False, is_from_partner=False,
                      is_falses_ml=False, force=True, raw=False):
        """
        Create an ANREV ticket for a specific task or multiple tasks based on
        the submitted file. Requires specific permissions.

        At least one of uuid/md5/sha1 must be provided. If both file-hashes are
        provided, they must match the same file.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param md5: the md5 hash of the submitted file.
        :param sha1: the sha1 hash of the submitted file.
        :param force: if True, enforce the generation of a ticket, even if none
            of the task-analysis rules would have generated a ticket
        :param min_score: Limit generation of tickets to tasks above the given
            threshold
        :param max_score: Limit generation of tickets to tasks below the given
            threshold
        :param summary: Optional summary (title) to use for the ticket.
        :param labels: Optional set of labels to assign to a task
        :param is_false_negative: Helper parameter to add the standard FN label
        :param is_false_positive: Helper parameter to add the standard FP label
        :param is_from_customer: Helper parameter to add the standard
            from-customer label
        :param is_from_partner: Helper parameter to add the standard
            from-partner label
        :param is_falses_ml: Helper parameter to add the standard falses-ml
            label
        :param raw: if True, return the raw JSON/XML results of the API query.
        """
        assert uuid or md5 or sha1, "Please provide task-uuid/md5/sha1"
        url = self._build_url('management', ['create_ticket'])
        if labels:
            labels = set(labels)
        else:
            labels = set()
        if is_false_negative:
            labels.add('false_negatives')
        if is_false_positive:
            labels.add('false_positives')
        if is_from_customer:
            labels.add('from-customer')
        if is_from_partner:
            labels.add('from-partner')
        if is_falses_ml:
            labels.add('falses-ml')
        if labels:
            labels_list = ','.join(labels)
        else:
            labels_list = None
        params = purge_none({
            'uuid': uuid,
            'md5': md5,
            'sha1': sha1,
            'min_score': min_score,
            'max_score': max_score,
            'force': force and 1 or 0,
            'summary': summary,
            'labels': labels_list,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def get_license_activity(self, query_start=None, query_end=None,
                             raw=False):
        """
        Fetch license activity information.

        DEPRECATED. DO NOT USE
        """
        #unused = query_start, query_end, raw
        assert False, "Call to deprecated API function"

    def get_api_utc_timestamp(self):
        """
        Query the API to get its UTC timestamp: do this *before* submitting
        to avoid racing or clock-skew with the local clock

        :returns: Current UTC timestamp according to API
        :rtype: `datetime.datetime`
        """
        start_info = self.get_completed(
            after='2039-12-31 23:59:59'
        )
        return parse_datetime(start_info['data']['before'])

    def get_status(self):
        """
        Get the status of malscape, indicating if all is ok or not

        :param raw: if True, return the raw JSON results of the API query.
        :returns: A dict with the load results:
            {
                'all_ok': An int which can be 0 or 1 indicating that everything is ok (1) or if
                    something is not correct (0) in malscape
            }
        """
        url = self._build_url('management', ['get_status'])
        return self._api_request(url)

    def ping(self, raw=False, verify=True):
        """
        Check if base API responds.
        """
        url = self._build_url('authentication', ['ping'])
        return self._api_request(url, raw=raw, verify=verify)


class AnalysisClient(AnalysisClientBase):
    """
    Client for the Analysis API.

    A client for the Analysis API that accesses the API through the web,
    using key and api token for authentication, and the python
    requests module for sending requests.

    NOTE: This class is not thread safe

    :param base_url: URL where the lastline analysis API is located. (required)
    :param key: API key for the Lastline Analyst API (required)
    :param api_token: API token for the Lastline Analyst API (required)
    :param logger: if provided, should be a python logging.Logger object
        or object with similar interface.
    :param ca_bundle: if provided, location of Certification Authority bundle
        to use for authentication. This should not be required
        if certificates are properly setup on the system.
    :param verify_ssl: if True, verify SSL certificates. This overrides the
        per-call parameter
    :param proxies: dictionay with per-protocol proxy to use to use
        (e.g. { 'http': 'localhost:3128', 'https': 'localhost:3128' }
    :param timeout: default timeout (in seconds) to use for network requests.
        Set to None to disable timeouts
    """

    # maximum unsuccessful login attempts in a row
    MAX_LOGIN_ATTEMPTS = 2

    def __init__(self,
                 base_url,
                 key,
                 api_token,
                 logger=None,
                 ca_bundle=None,
                 verify_ssl=True,
                 use_curl=False,
                 timeout=60,
                 proxies=None,
                 config=None):
        AnalysisClientBase.__init__(self, base_url, logger, config)
        self.__key = key
        self.__api_token = api_token
        self.__ca_bundle = ca_bundle
        self.__verify_ssl = verify_ssl
        self.__logger = logger
        self.__timeout = timeout
        if use_curl and logger:
            logger.warning("Ignoring deprecated use_curl option")
        if proxies is None and config:
            self.__proxies = get_proxies_from_config(config)
        else:
            self.__proxies = proxies
        self.__session = None

    def set_key(self, key):
        self.__key = key
        self._logout()

    def set_api_token(self, api_token):
        self.__api_token = api_token
        self._logout()

    def set_ssl_verification(self, value=True):
        """
        Allow enabling/disabling SSL verification on the fly
        """
        self.__verify_ssl = value

    def _login(self):
        """
        Creates auth session for malscape-service.
        """
        self.__session = requests.session()
        url = self._build_url('authentication', ['login'])
        params = {'key': self.__key}
        if self.__api_token:
            params['api_token'] = self.__api_token
        try:
            self._api_request(url=url, params=params, post=True, verify=self.__verify_ssl)
        except FailedRequestError as exc:
            if exc.status_code() != 404:
                raise
            if self._logger():
                self._logger().debug("Login raised %s: switching to legacy authentication", exc)
            # the API does not support the login call, and thus not session-based authentication.
            # Switch to embedding credentials in each request
            self.__session = MockSession(credentials=params, logger=self._logger())

    def _logout(self):
        """
        Destroys auth session for malscape-service.
        """
        if not self.__session:
            return
        self.__session.close()
        self.__session = None

    def _save_stream_positions(self, files):
        """
        Stores stream_positions for files

        :param files: dictionary with filestreams, according to requests.request 'files' parameter
        :type files: `dict`
        :return: dictionary with filenames and according stream positions
        :rtype: `dict`
        """
        result = {}
        if not files:
            return result
        for file_name, file_object in files.iteritems():
            # 'files' value can be tuple or file-like object, according to python-requests docs
            if isinstance(file_object, tuple):
                file_stream = file_object[1]
            else:
                file_stream = file_object
            result[file_name] = file_stream.tell()
        return result

    def _restore_stream_positions(self, stream_positions, files):
        """
        Restores stream positions, saved earlier

        :param stream_positions: dictionary 'filename: position'
        :type stream_positions: `dict`
        :param files: dictionary with filestreams, according to requests.request 'files' parameter
        :type files: `dict`
        """
        for file_name, stream_position in stream_positions.iteritems():
            file_object = files[file_name]
            if isinstance(file_object, tuple):
                file_stream = file_object[1]
            else:
                file_stream = file_object
            file_stream.seek(stream_position)

    def _api_request(self,
                     url,
                     params=None,
                     files=None,
                     timeout=None,
                     post=False,
                     raw=False,
                     requested_format="json",
                     verify=True):
        # first, perform authentication, if we have no session
        if not self.__session:
            self._login()

        if self._logger():
            self._logger().info("Requesting %s" % url)
        if not params:
            params = {}

        # we allow anyone setting this flag, but only admins will get any data back
        if self.REQUEST_PERFDATA:
            params['perfdata'] = 1

        method = "GET"
        data = None
        if post or files:
            method = "POST"
            data = params
            params = None

        if not self.__verify_ssl or not verify:
            verify_ca_bundle = False
        elif self.__ca_bundle:
            verify_ca_bundle = self.__ca_bundle
        else:
            verify_ca_bundle = True

        # save stream positions in case of reauthentication
        stream_positions = self._save_stream_positions(files)
        # start authentication / reauthentication loop
        login_attempt = 1
        while True:
            try:
                response = self.__session.request(
                    method, url,
                    params=params, data=data, files=files,
                    timeout=timeout or self.__timeout,
                    verify=verify_ca_bundle,
                    proxies=self.__proxies)
                # raise if anything went wrong
                response.raise_for_status()

            #NOTE: Fixed to support python3
            except (requests.HTTPError) as exc:
                if self.__logger:
                    self.__logger.warning("HTTP Error contacting Lastline Analyst API: %s", exc)
                if exc.response is not None:
                    status_code = exc.response.status_code
                    msg = exc.response.text
                else:
                    status_code = None
                    msg = None
                # raise a wrapped exception
                raise FailedRequestError(msg=msg, error=exc, status_code=status_code)

            #NOTE: Fixed to support python3
            #except requests.RequestException, exc:
            except (requests.RequestException) as exc:
                if self.__logger:
                    self.__logger.warning("Error contacting Lastline Analyst API: %s", exc)
                # raise a wrapped exception
                raise CommunicationError(error=exc)

            # Get the response content, as a unicode string if the response is
            # textual, as a regular string otherwise.
            content_type = response.headers.get("content-type")
            if content_type and (
                        content_type.startswith("application/json") or
                        content_type.startswith("text/")):
                response_data = response.text
            else:
                response_data = response.content

            # Get the response disposition if defined
            disposition = None
            content_disposition = response.headers.get("content-disposition")
            if content_disposition:
                # Always returns a couple type, params even if
                # no parameters are provided or the string is empty
                disp_type, disp_params = cgi.parse_header(content_disposition)
                if disp_type:
                    disposition = {'type': disp_type.lower(),
                                   'params': disp_params}

            try:
                response_result = self._process_response_page(
                    response_data, raw, requested_format, disposition)
                # if all goes well, just return result
                return response_result
            except AuthenticationError:
                self._logout()

                # if this is not a real session, we have embedded the credentials in the request
                # and retrying won't change anything
                if isinstance(self.__session, MockSession):
                    raise

                # don't try more than N times - we essentially need to only retry establishing a
                # session, so N>2 doesn't make too much sense
                if login_attempt >= self.MAX_LOGIN_ATTEMPTS:
                    raise AuthenticationError(
                        'login failed for {} times'.format(self.MAX_LOGIN_ATTEMPTS))

                if self.__logger:
                    self.__logger.warning('attempting to restore connection for %d time',
                                          login_attempt)
                self._login()
                self._restore_stream_positions(stream_positions, files)
                login_attempt += 1


class SubmittedTask(object):
    """
    Representation of a task that was submitted
    """
    def __init__(self, task_uuid, score=None, error=None, error_exception=None):
        """
        :param task_uuid: The returned task-UUID, if one was returned
        :type task_uuid: `str` | None
        :param score: The returned score, if one is available
        :type score: `int` | None
        :param error: The returned error, if submission failed
        :type error: `str` | None
        :param error_exception: Detailed exception data, if submission failed
        :type error_exception: `AnalysisAPIError` | None
        """
        self.__task_uuid = task_uuid
        self.__error = error
        self.__error_exception = error_exception
        self.__score = score

    @property
    def task_uuid(self):
        return self.__task_uuid

    @property
    def error(self):
        return self.__error

    @property
    def error_exception(self):
        return self.__error_exception

    @property
    def score(self):
        if self.__score is not None:
            return self.__score
        if self.error:
            return 0
        raise NoResultFoundError("Task not complete")

    def set_score(self, score):
        """
        Update the score of this task. May only be done if not set yet (see
        `self.is_complete()`).

        :param score: Score to set
        :type score: `int`
        """
        if self.__score is not None:
            raise Error("Double-setting score")
        if 0 <= score <= 100:
            self.__score = int(score)
        else:
            raise Error("Invalid score")

    def is_complete(self):
        """
        Check if this task represents a complete task

        :returns: True if this task is marked completed, False otherwise.
        :rtype: `bool`
        """
        return self.__score is not None or self.__error is not None

    def __eq__(self, other):
        return isinstance(other, SubmittedTask) and other.task_uuid == self.task_uuid

    def __str__(self):
        s = "AnalysisTask"
        if self.task_uuid:
            s += " {}".format(self.task_uuid)
        if self.error_exception:
            s += "(error: {})".format(self.error_exception)
        elif self.error:
            s += "(error: {})".format(self.error)
        elif self.__score is not None:
            s += "(score: {})".format(self.__score)
        return s


class SubmittedFileTask(SubmittedTask):
    """
    Representation of a file task that was submitted
    """
    def __init__(self, file_md5, file_sha1, file_sha256, task_uuid,
                 filename=None, score=None, error=None, error_exception=None):
        """
        :param file_md5: The MD5 of the submitted file
        :type file_md5: `str`
        :param file_sha1: The SHA1 of the submitted file
        :type file_sha1: `str`
        :param file_sha256:  The SHA256 of the submitted file
        :type file_sha256: `str`
        :param task_uuid: The returned task-UUID, if one was returned
        :type task_uuid: `str` | None
        :param filename: The name of the file that was submitted
        :type filename: `str` | None
        :param score: The returned score, if one is available
        :type score: `int` | None
        :param error: The returned error, if submission failed
        :type error: `str` | None
        :param error_exception: Detailed exception data, if submission failed
        :type error_exception: `AnalysisAPIError` | None
        """
        if not file_md5 or len(file_md5) != 32:
            raise ValueError("Invalid file MD5")
        if not file_sha1 or len(file_sha1) != 40:
            raise ValueError("Invalid file SHA1")
        if not file_sha256 or len(file_sha256) != 64:
            raise ValueError("Invalid file SHA256")
        SubmittedTask.__init__(
            self,
            task_uuid=task_uuid,
            score=score,
            error=error,
            error_exception=error_exception
        )
        self.__file_md5 = file_md5
        self.__file_sha1 = file_sha1
        self.__file_sha256 = file_sha256
        self.__filename = filename

    @property
    def file_md5(self):
        return self.__file_md5

    @property
    def file_sha1(self):
        return self.__file_sha1

    @property
    def file_sha256(self):
        return self.__file_sha256

    @property
    def filename(self):
        return self.__filename

    def __str__(self):
        s = "%s: MD5=%s, SHA1=%s" % (
            SubmittedTask.__str__(self),
            self.file_md5,
            self.file_sha1,
        )
        if self.file_sha256:
            s += ", SHA256=%s" % self.file_sha256
        if self.filename:
            s += ", name=%s" % self.filename
        return s


class SubmittedURLTask(SubmittedTask):
    """
    Representation of a URL task that was submitted
    """
    def __init__(self, url, task_uuid, referer=None, score=None, error=None, error_exception=None):
        """
        :param url: The URL that was submitted
        :type url: `str`
        :param task_uuid: The returned task-UUID, if one was returned
        :type task_uuid: `str` | None
        :param referer:  The refer(r)er which was submitted for the URL
        :type referer: `str`
        :param score: The returned score, if one is available
        :type score: `int` | None
        :param error: The returned error, if submission failed
        :type error: `str` | None
        :param error_exception: Detailed exception data, if submission failed
        :type error_exception: `AnalysisAPIError` | None
        """
        SubmittedTask.__init__(
            self,
            task_uuid=task_uuid,
            score=score,
            error=error,
            error_exception=error_exception
        )
        self.__url = url
        self.__referer = referer

    @property
    def url(self):
        return self.__url

    @property
    def referer(self):
        return self.__referer

    def __str__(self):
        s = "%s: URL=%s" % (
            SubmittedTask.__str__(self),
            self.url,
        )
        if self.referer:
            s += ", refer(r)er=%s" % self.referer
        return s


class SubmissionHelper(object):
    """
    Helper class for handling submission and task retrieval
    """
    def __init__(self, analysis_client, logger=None, num_retries=10):
        """
        :param analysis_client: The client to use
        :type analysis_client: `AnalysisClientBase`
        :param logger: Optional logger to use. If None is provided, log to
            stdout
        :type logger: logging.Logger
        :param num_retries: Number of times to retry network requests on error.
            Use 0 to disable retries or None for endless retries
        :type num_retries: int
        """
        self.__analysis_client = analysis_client
        self.__num_retries = num_retries
        if logger:
            self.__logger = logger
        else:
            self.__logger = logging.getLogger('lastline.analysis.api_client')
            self.__logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            self.__logger.addHandler(ch)

    def get_api_utc_timestamp(self):
        """
        Query the API to get its UTC timestamp: do this *before* submitting
        to avoid racing or clock-skew with the local clock

        :returns: Current UTC timestamp according to API
        :rtype: `datetime.datetime`
        """
        return self.__analysis_client.get_api_utc_timestamp()

    def submit_file_stream(self, file_stream, **kwargs):
        """
        Submit a file for analysis and retrieve results if they are immediately
        available. Additional parameters passed to this function are forwarded
        to the client (see `submit_file_hash` or `submit_file`).

        NOTE: To avoid a race-condition between submission and polling for
        results, use the following approach::

            helper = SubmissionHelper(<client>)
            ts = helper.get_api_utc_timestamp()
            submission = helper.submit_file_stream(<stream>)
            helper.wait_for_completion_of_submission(submission, ts)

        or use the `submit_file_streams_and_wait_for_completion()` helper
        function.

        NOTE: You may provide any of the parameters
        - file_md5,
        - file_sha1, or
        - file_sha256
        to avoid repeated file-hash calcations. Any hash not provided will be
        generated from the given file-stream.

        :param file_stream: Stream to submit
        :type file_stream: `stream`
        :returns: Submission results
        :rtype: `SubmittedFileTask`
        """
        # get the current seek position to put the stream back to exactly
        # this point after reading the file for computing hashes
        file_pos = file_stream.tell()
        try:
            file_md5 = kwargs.pop('file_md5')
            if not file_md5: raise KeyError()
        except KeyError:
            file_md5 = hash_stream(file_stream, 'md5')
            file_stream.seek(file_pos)
        try:
            file_sha1 = kwargs.pop('file_sha1')
            if not file_sha1: raise KeyError()
        except KeyError:
            file_sha1 = hash_stream(file_stream, 'sha1')
            file_stream.seek(file_pos)
        try:
            file_sha256 = kwargs.pop('file_sha256')
            if not file_sha256: raise KeyError()
        except KeyError:
            file_sha256 = hash_stream(file_stream, 'sha256')
            file_stream.seek(file_pos)

        try:
            filename = kwargs.pop('filename')
        except KeyError:
            if hasattr(file_stream, 'name'):
                filename = path.basename(file_stream.name)
            else:
                # auto-select in the API
                filename = None

        # submit_file_hash does not take the "delete_after_analysis" parameter
        try:
            delete_after_analysis = kwargs.pop('delete_after_analysis')
        except KeyError:
            delete_after_analysis = False
        # same for "mime_type" (only for submit_file_hash)
        try:
            mime_type = kwargs.pop('mime_type')
        except KeyError:
            mime_type = None
        self.__logger.info("Submitting file %s (md5=%s, sha1=%s, sha256=%s)",
                           filename or '<unnamed>', file_md5, file_sha1,
                           file_sha256)
        result_data = None
        task_uuid = None
        score = None
        error = None
        error_exception = None
        try:
            result_data = self.__analysis_client.submit_file_hash(
                md5=file_md5, sha1=file_sha1, sha256=file_sha256,
                filename=filename,
                full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                mime_type=mime_type,
                **kwargs
            )['data']
        except AnalysisAPIError as err:
            self.__logger.debug("Submitting file by hash failed: %s", err)
            # NOTE: In theory we should only submit again if the file is not
            # known, but submitting again either way does not hurt
            try:
                result_data = self.__analysis_client.submit_file(
                    file_stream=file_stream,
                    filename=filename,
                    full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                    delete_after_analysis=delete_after_analysis,
                    **kwargs
                )['data']
            except AnalysisAPIError as err2:
                # we are handling this error, and it's not a bug in the code, so
                # logged just as warning
                self.__logger.warning(
                    "Submitting file %s (md5=%s, sha1=%s, sha256=%s) failed: %s",
                    filename or '<unnamed>', file_md5, file_sha1, file_sha256, err2)

                error = str(err2)
                error_exception = err2

        if result_data is not None:
            try:
                task_uuid = result_data['task_uuid']
            except KeyError:
                # this path is not possible according to the API documentation,
                # but just to be on the save side...
                error = "No task returned"
            score = result_data.get('score')

        # NOTE: We insert the data we have already now right away. This way the
        # caller can skip waiting for completion if possible
        return SubmittedFileTask(
            file_md5=file_md5,
            file_sha1=file_sha1,
            file_sha256=file_sha256,
            filename=filename,
            task_uuid=task_uuid,
            score=score,
            error=error,
            error_exception=error_exception
        )

    def submit_filename(self, filename, **kwargs):
        """
        Submit a file for analysis and retrieve results if they are immediately
        available. Additional parameters passed to this function are forwarded
        to the client (see `submit_file_hash` or `submit_file`).

        NOTE: To avoid a race-condition between submission and polling for
        results, use the following approach::

            helper = SubmissionHelper(<client>)
            ts = helper.get_api_utc_timestamp()
            submission = helper.submit_filename(<filename>)
            helper.wait_for_completion_of_submission(submission, ts)

        or use the `submit_filenames_and_wait_for_completion()` helper function.

        :param filename: File on the local filesystem to submit
        :type filename: `str`
        :returns: Submission results
        :rtype: `SubmittedFileTask`
        """
        with open(filename) as file_stream:
            return self.submit_file_stream(file_stream, **kwargs)

    def submit_url(self, url, **kwargs):
        """
        Submit a URL for analysis and retrieve results if they are immediately
        available. Additional parameters passed to this function are forwarded
        to the client (see `submit_url`).

        NOTE: To avoid a race-condition between submission and polling for
        results, use the following approach::

            helper = SubmissionHelper(<client>)
            ts = helper.get_api_utc_timestamp()
            submission = helper.submit_url(<url>, referer=<referer>)
            helper.wait_for_completion_of_submission(submission, ts)

        or use the `submit_urls_and_wait_for_completion()` helper function.

        :param url: URL to submit
        :type url: `str`
        :returns: Submission results
        :rtype: `SubmittedURLTask`
        """
        self.__logger.info("Submitting URL %s", url)
        result_data = None
        task_uuid = None
        score = None
        error = None
        error_exception = None
        try:
            result_data = self.__analysis_client.submit_url(
                url=url,
                full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                **kwargs
            )['data']
        except AnalysisAPIError as err:
            # we are handling this error, and it's not a bug in the code, so
            # logged just as warning
            self.__logger.warning("Submitting URL %s failed: %s", url, err)
            error = str(err)
            error_exception = err

        if result_data is not None:
            try:
                task_uuid = result_data['task_uuid']
            except KeyError:
                # this path is not possible according to the API documentation,
                # but just to be on the save side...
                error = "No task returned"
            score = result_data.get('score')

        # NOTE: We insert the data we have already now right away. This way the
        # caller can skip waiting for completion if possible
        return SubmittedURLTask(
            url=url,
            referer=kwargs.get('referer'),
            task_uuid=task_uuid,
            score=score,
            error=error,
            error_exception=error_exception
        )

    def submit_file_streams_and_wait_for_completion(
            self, file_streams,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            **kwargs):
        """
        Submit a list of files and wait for completion: For each file, submit
        the file for analysis, wait for completion, and retrieve results.
        Additional parameters passed to this function are forwarded to the
        client (see `submit_file_hash` or `submit_file`).

        :param file_streams: List of streams to submit
        :type file_streams: `list`(`stream`)
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for long than this many
            seconds for completion. If None is specified, wait forever.
            NOTE: If waiting times out, the result will contain elements whose
            score is set to `None`. This method does *not* raise
            `WaitResultTimeout` to allow retrieving the result even when waiting
            for completion timed out.
        :type wait_completion_max_seconds: `float`
        :returns: Dictionary of results
        :rtype: `dict`(`SubmittedFileTask`)
        """
        start_ts = self.get_api_utc_timestamp()

        self.__logger.info("Submitting %d files", len(file_streams))
        results = {}
        for file_stream in file_streams:
            # the caller may want to submit all files using the same
            # filename, so we really forward *all* arguments
            results[file_stream] = self.submit_file_stream(
                file_stream=file_stream, **kwargs
            )

        try:
            self.wait_for_completion(
                results,
                start_timestamp=start_ts,
                wait_completion_interval_seconds=
                    wait_completion_interval_seconds,
                wait_completion_max_seconds=wait_completion_max_seconds,
                verify=kwargs.get('verify', True)
            )
        except WaitResultTimeout as err:
            self.__logger.warning("Waiting for file submissions completion "
                                  "failed: %s", err)
        return results

    def submit_filenames_and_wait_for_completion(
            self, filenames,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            **kwargs):
        """
        Submit a list of files and wait for completion: For each file, submit
        the file for analysis, wait for completion, and retrieve results.
        Additional parameters passed to this function are forwarded to the
        client (see `submit_file_hash` or `submit_file`).

        :param filenames: List of files on the local filesystem to submit
        :type filenames: `list`(`str`)
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for long than this many
            seconds for completion. If None is specified, wait forever.
            NOTE: If waiting times out, the result will contain elements whose
            score is set to `None`. This method does *not* raise
            `WaitResultTimeout` to allow retrieving the result even when waiting
            for completion timed out.
        :type wait_completion_max_seconds: `float`
        :returns: Dictionary of results
        :rtype: `dict`(`SubmittedFileTask`)
        """
        file_streams = {}
        try:
            # NOTE: use set() to make sure the list is unique
            for filename in set(filenames):
                file_streams[open(filename)] = filename

            results_streams = self.submit_file_streams_and_wait_for_completion(
                file_streams=file_streams.keys(),
                wait_completion_interval_seconds=
                    wait_completion_interval_seconds,
                wait_completion_max_seconds=wait_completion_max_seconds,
                **kwargs
            )
            # map by-stream results into by-name results
            results = {}
            #NOTE: Fixed to support python3
            #for file_stream, result in results_streams.iteritems():
            for file_stream, result in results_streams.items():
                filename = file_streams[file_stream]
                results[filename] = result
            return results
        finally:
            for file_stream in file_streams:
                file_stream.close()

    def submit_urls_and_wait_for_completion(
            self, urls,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            **kwargs):
        """
        Submit a list of URLs and wait for completion: For each URL, submit
        the URL for analysis, wait for completion, and retrieve results.
        Additional parameters passed to this function are forwarded to the
        client (see `submit_url`).

        :param urls: List of URLs to submit
        :type urls: `list`(`str`)
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for long than this many
            seconds for completion. If None is specified, wait forever
        :type wait_completion_max_seconds: `float`
        :returns: Dictionary of results
        :rtype: `dict`(`SubmittedURLTask`)
        :raises WaitResultTimeout: Waiting for results timed out
        """
        start_ts = self.get_api_utc_timestamp()

        self.__logger.info("Submitting %d URLs", len(urls))
        results = {}
        for url in urls:
            self.__logger.info("Submitting URL %s", url)
            results[url] = self.submit_url(url, **kwargs)

        try:
            self.wait_for_completion(
                results,
                start_timestamp=start_ts,
                wait_completion_interval_seconds=
                    wait_completion_interval_seconds,
                wait_completion_max_seconds=wait_completion_max_seconds,
                verify=kwargs.get('verify', True)
            )
        except WaitResultTimeout as err:
            self.__logger.warning("Waiting for URL submissions completion "
                                  "failed: %s", err)
        return results

    def wait_for_completion_of_submission(
            self, submission, start_timestamp,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            verify=True):
        """
        Wait for completion of a given tasks.

        :param submission: A submitted task. This object is updated in place
            with result data
        :type submission: `SubmittedTask`
        :param start_timestamp: UTC timestamp before the first submission has
            happened. Use `self.get_api_utc_timestamp()` to retrieve
        :type start_timestamp: `datetime.datetime`
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for long than this many
            seconds for completion. If None is specified, wait forever
        :type wait_completion_max_seconds: `float`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :raises WaitResultTimeout: Waiting for results timed out
        """
        self.wait_for_completion(
            submissions={1:submission},
            start_timestamp=start_timestamp,
            wait_completion_interval_seconds=wait_completion_interval_seconds,
            wait_completion_max_seconds=wait_completion_max_seconds,
            verify=verify,
        )

    def wait_for_completion(
            self, submissions, start_timestamp,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            verify=True):
        """
        Wait for completion of a given dictionary of tasks.

        NOTE: Results are filled in in provided `submissions` dictionary.

        :param submissions: Dictionary of submissions: submission identifier to
            `SubmittedTask` mapping. NOTE: The submission identifier can be an
            arbitrary value unique to the dictionary
        :type submissions: `dict`(id:`SubmittedTask`)
        :param start_timestamp: UTC timestamp before the first submission has
            happened. Use `self.get_api_utc_timestamp()` to retrieve
        :type start_timestamp: `datetime.datetime`
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for long than this many
            seconds for completion. If None is specified, wait forever
        :type wait_completion_max_seconds: `float`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :raises WaitResultTimeout: Waiting for results timed out
        """
        g = self.yield_completed_tasks(
                submissions, start_timestamp,
                wait_completion_interval_seconds=wait_completion_interval_seconds,
                wait_completion_max_seconds=wait_completion_max_seconds,
                verify=verify)
        # wait for completion all the tasks by invoking generator
        for _ in g:
            pass

    def yield_completed_tasks(
            self, submissions, start_timestamp,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            verify=True):
        """
        Returns a generator, which gives completed tasks as soon as they are
        ready.

        NOTE: Results are filled in in provided `submissions` dictionary.

        NOTE: Any `SubmittedTask` instances that are part of the `submissions`
        parameter and that are marked as completed already upon function
        invocation will not be yielded.

        :param submissions: Dictionary of submissions: submission identifier to
            `SubmittedTask` mapping. NOTE: The submission identifier can be an
            arbitrary value unique to the dictionary
        :type submissions: `dict`(id:`SubmittedTask`)
        :param start_timestamp: UTC timestamp before the first submission has
            happened. Use `self.get_api_utc_timestamp()` to retrieve
        :type start_timestamp: `datetime.datetime`
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for long than this many
            seconds for completion. If None is specified, wait forever
        :type wait_completion_max_seconds: `float`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :raises WaitResultTimeout: Waiting for results timed out
        :returns: generator that yields completed SubmittedTask objects
        :rtype: `Iterator`(`SubmittedTask`)
        """
        # find which submissions we're still waiting for and build an index for
        # looking up existing data quickly
        missing_results = {
            result.task_uuid: submission_id
            for submission_id, result in submissions.iteritems()
            if result.task_uuid is not None and not result.is_complete()
        }
        if not missing_results:
            self.__logger.info("No need to wait for completion for any of %d "
                               "submissions", len(submissions))
            return

        self.__logger.info("Waiting for completion of %d/%d submissions",
                           len(missing_results), len(submissions))

        start_completion_time = time.time()
        end_completion_time = (
            start_completion_time + wait_completion_max_seconds
            if wait_completion_max_seconds is not None else None
        )
        # Number of times to re-sending request
        num_retries = self.__num_retries
        while missing_results:
            self.__logger.debug("Waiting for completion of %d submissions",
                                len(missing_results))
            try:
                completed_data = self.__analysis_client.get_completed(
                    after=start_timestamp,
                    verify=verify,
                    include_score=True
                )['data']
            # only ignore the communication error and resending the request
            except CommunicationError as e:
                # if num_retries is None, we will do endless retries
                if num_retries > 0 or num_retries is None:
                    if num_retries is not None:
                        num_retries -= 1
                        self.__logger.warning("Bad Communication. Retry sending request... "
                                              "%d times left!\n", num_retries)
                    else:
                        self.__logger.warning("Bad Communication. Retry sending request... "
                                              "UNLIMITED times left!\n")
                else:
                    self.__logger.warning("Communication error: %s", e)
                    raise
            else:
                # reset times of retry to the default value if is not None
                if self.__num_retries is not None:
                    num_retries = self.__num_retries
                # resume from here next iteration:
                start_timestamp = completed_data['before']
                if completed_data['tasks']:
                    for task_uuid, score in completed_data['tasks'].iteritems():
                        try:
                            submission_id = missing_results[task_uuid]
                        except KeyError:
                            # someone else is submitting with the same license or
                            # we already had the result
                            continue

                        self.__logger.debug("Got result for task %s", task_uuid)
                        # fill in the details
                        #
                        # NOTE: We're currently NOT checking if the analysis failed.
                        # this will be merged with "score=0" - it's up to the caller
                        # to check (or a future extension)
                        result = submissions[submission_id]
                        result.set_score(score) # result.is_complete() becomes True
                        del missing_results[task_uuid]
                        self.__logger.debug("Got result for task %s: %s",
                                            task_uuid, result)
                        yield result
                if not missing_results:
                    break
                if completed_data['more_results_available']:
                    # If we have more results available to be fetched, don't need to sleep
                    continue

            sleep_timeout = wait_completion_interval_seconds
            if end_completion_time is not None:
                now = time.time()
                if now >= end_completion_time:
                    self.__logger.warning("Waiting for completion of %d "
                                          "submissions timed out",
                                          len(missing_results))
                    raise WaitResultTimeout()
                # make sure we only sleep as long as we have time left before
                # the timeout
                if now + sleep_timeout > end_completion_time:
                    sleep_timeout = end_completion_time - now
            time.sleep(sleep_timeout)

        self.__logger.info("Done waiting for completion of %d submissions",
                           len(submissions))


class QueryHelper(object):
    """
    Helper class for handling queries
    """
    def __init__(self, analysis_client, logger=None):
        """
        :param analysis_client: The client to use
        :type analysis_client: `AnalysisClientBase`
        :param logger: Optional logger to use. If None is provided, log to
            stdout
        :type logger: logging.Logger
        """
        self.__analysis_client = analysis_client
        if logger:
            self.__logger = logger
        else:
            self.__logger = logging.getLogger('lastline.analysis.api_client')
            self.__logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            self.__logger.addHandler(ch)

    def download_analysis_subject_file(self, task_uuid):
        """
        Helper method for checking if a file analysis subject is available for
        download

        :param task_uuid: The task's UUID
        :type task_uuid: `str`
        :returns: A file-stream if the file is available, otherwise None
        :rtype: `NamedStringIO`
        """
        results = self.__analysis_client.get_result(
            uuid=task_uuid,
            full_report_score=ANALYSIS_API_NO_REPORT_DETAILS)
        try:
            reports = results['data']['reports']
        except KeyError:
            reports = None
        if not reports:
            return None

        for report in reports:
            report_uuid = report.get('report_uuid')
            if report_uuid:
                try:
                    stream = self.__analysis_client.get_result_artifact(
                        uuid=task_uuid,
                        report_uuid=report_uuid,
                        artifact_name='analysis_subject')
                except Error:
                    stream = None
                if stream:
                    return stream
        return None

    def download_analysis_subject_by_file_hash(self, md5=None, sha1=None,
                                               sha256=None):
        """
        Helper method for checking if a file is available for download

        :param md5: Optional md5 hash of the file. Exactly one of the file-hash
            parameters must to be provided
        :type md5: `str`
        :param sha1: Optional sha1 hash of the file. Exactly one of the file-
            hash parameters must to be provided
        :type sha1: `str`
        :param sha256: Optional sha256 hash of the file. Exactly one of the
            file-hash parameters must to be provided
        :type sha256: `str`
        :returns: A file-stream if the file is available, otherwise None
        :rtype: `NamedStringIO`
        """
        result = self.__analysis_client.query_file_hash(
            md5=md5,
            sha1=sha1,
            sha256=sha256)
        if not result['data']['files_found']:
            return None
        return self.download_analysis_subject_file(
            task_uuid=result['data']['tasks'][0]['task_uuid'])


#############################################################################
#
# END API-CLIENT FUNCTIONALITY
#
# START API-SHELL FUNCTIONALITY
#
# NOTE: We only keep this code in this module for backwards-compatibility
import sys
import optparse


def init_shell(banner):
    """Set up the iPython shell."""
    # NOTE: We use a local import here to avoid requiring IPython when just using the
    # module without the shell
    try:
        # pylint: disable=E0611,F0401
        from IPython.frontend.terminal import embed
        shell = embed.InteractiveShellEmbed(banner1=banner)
    except ImportError: # iPython < 0.11
        import IPython
        # pylint: disable=E1101
        # pylint won't find the class if a newer version is installed
        shell = IPython.Shell.IPShellEmbed()
        shell.set_banner(banner)
    return shell


def main(argv):
    deprecation_notice = "** DEPRECATION NOTICE: USE analysis_apiclient_shell.py INSTEAD **"
    parser = optparse.OptionParser(usage="""
{deprecation_notice}

Run client for analysis api with the provided credentials

    %prog access_key api_token

{deprecation_notice}
""".format(deprecation_notice=deprecation_notice))
    parser.add_option("-u", "--api-url", dest="api_url",
        type="string", default="https://analysis.lastline.com",
        help="send API requests to this URL (debugging purposes)")

    (cmdline_options, args) = parser.parse_args(argv[1:])
    if len(args) != 2:
        parser.print_help()
        return 1

    namespace = {}
    namespace["analysis"] = AnalysisClient(cmdline_options.api_url,
                                           key=args[0],
                                           api_token=args[1])

    shell = init_shell(banner=deprecation_notice)
    shell(local_ns=namespace, global_ns=namespace)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
