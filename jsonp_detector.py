from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IParameter
from burp import IScannerInsertionPoint
from array import array
from time import sleep

CALLBACK_PARAMS = ['callback', 'cb', 'jsonp', 'jsonpcallback', 'jcb', 'call']

class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("JSONP Detector")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    #
    # implement IScannerCheck
    #

    def doPassiveScan(self, baseRequestResponse):
        requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
        responseInfo = self._helpers.analyzeResponse(baseRequestResponse.getResponse())

        res = []

        if responseInfo.getInferredMimeType() == 'script':
            # debug
            print('passive', self._helpers.analyzeRequest(baseRequestResponse).getUrl(), responseInfo.getInferredMimeType())
            for param in requestInfo.getParameters():
                if (
                    param.getType() == IParameter.PARAM_URL and \
                    param.getName() in CALLBACK_PARAMS
                ):
                    # debug
                    print('detect', self._helpers.analyzeRequest(baseRequestResponse).getUrl(), responseInfo.getInferredMimeType())
                    issue_detail = 'Passively detect jsonp endpoint'

                    res.append(
                        CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse],
                            'JSONP Endpoint',
                            issue_detail,
                            'Medium'
                        )
                    )
        elif (
            requestInfo.getMethod() == 'GET' and \
            responseInfo.getInferredMimeType() == 'JSON'
        ):
            # debug
            print('active', self._helpers.analyzeRequest(baseRequestResponse).getUrl(), responseInfo.getInferredMimeType())

            detected_checkRequestResponse = []
            # add callback param to request and fire
            for param_name in CALLBACK_PARAMS:
                callback_param = \
                    self._helpers.buildParameter(
                        param_name,
                        'myCallbackkk',
                        IParameter.PARAM_URL
                    )

                rawRequest = baseRequestResponse.getRequest()
                checkRequest = self._helpers.addParameter(rawRequest, callback_param)
                checkRequestResponse = self._callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(), checkRequest)

                checkResponse = self._helpers.analyzeResponse(checkRequestResponse.getResponse())

                if (callback_param.getValue() in self._helpers.bytesToString(checkRequestResponse.getResponse())):
                    # debug
                    print('detect', self._helpers.analyzeRequest(baseRequestResponse).getUrl(), callback_param.getName(), checkResponse.getInferredMimeType())
                    detected_checkRequestResponse.append(checkRequestResponse)
                elif checkResponse.getInferredMimeType() != 'JSON':
                    # debug
                    print('potential', self._helpers.analyzeRequest(baseRequestResponse).getUrl(), callback_param.getName(), checkResponse.getInferredMimeType())
                    detected_checkRequestResponse.append(checkRequestResponse)
                sleep(1)

            if len(detected_checkRequestResponse) != 0:
                issue_detail = 'Actively detect jsonp endpoint (or potential)'
                res.append(
                    CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        detected_checkRequestResponse,
                        'JSONP Endpoint',
                        issue_detail,
                        'Medium'
                    )
                )


        return res if res else None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
