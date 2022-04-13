import json
import logging
import os

import requests

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)s %(levelname)s %(message)s',
                    filename='outlog.log'
                    )
logger = logging.getLogger(__name__)
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

class Session(object):
    """
    Session class for instantiating a logged in session
    for VMware Cloud Services.

    Requires refresh token from VMware Cloud Services portal to instantiate.
    """
    def __init__(self, auth_token):
        self.token = auth_token
        self.headers = {'Content-Type': 'application/json',
                        'Authorization': f'Bearer {self.token}'}
        self.baseurl = 'https://lab-vra.meteialab.com'

    @classmethod
    def login(self, refresh_token):
            baseurl = 'https://lab-vra.meteialab.com'
            uri = f'/iaas/api/login'
            headers = {'Content-Type': 'application/json'}
            payload = {"refreshToken":refresh_token}
            logger.debug(f'POST to: {baseurl}{uri} '
                         f'with headers: {headers} '
                         f'and body: {payload}.'
                         )

            try:
                r = requests.post(f'{baseurl}{uri}',
                                  headers=headers,
                                  json=payload,
                                  verify=False)
                logger.debug(f'Response: {r.json()}')
                r.raise_for_status()
                logger.info('Authenticated successfully.')
                auth_token = r.json()['token']
                return self(auth_token)
            except requests.exceptions.HTTPError:
                logger.error('Failed to authenticate.')
                logger.error(f'Error message {r.json()["message"]}',
                             exc_info=False)

    def _request(self,
                 url,
                 request_method='GET',
                 payload=None,
                 **kwargs
                 ):
        """
        Inspired by the work of Russell Pope.
        :param url: The complete uri for the requested resource.
        You must include the leading /
        :param request_method: An HTTP method that one of
        PUT, POST, PATCH, DELETE or GET
        :param payload: Used to store a resource that is used in either
        POST, PATCH or PUT operations
        :param kwargs: Unused currently
        :return: The response JSON
        """

        if request_method in ('PUT', 'POST', 'PATCH') and payload:
            if type(payload) == dict:
                payload = json.dumps(payload)
            try:
                r = requests.request(request_method,
                                     url=url,
                                     headers=self.headers,
                                     data=payload,
                                     verify=False)
                logger.debug(f'{request_method} to {url} '
                             f'with headers {self.headers} '
                             f'and body {payload}.'
                             )
                logger.debug(f'Request response: {r.json()}')
                r.raise_for_status()
                return r.json()
            except requests.exceptions.HTTPError:
                logger.error(r.json(),
                             exc_info=False
                             )

        elif request_method == 'GET':
            try:
                r = requests.request(request_method,
                                     url=url,
                                     headers=self.headers)
                logger.debug(f'{request_method} to {url} '
                             f'with headers {self.headers}.'
                             )
                logger.debug(f'Request response: {r.json()}')
                r.raise_for_status()
                return r.json()
            except requests.exceptions.HTTPError:
                logger.error(r.json()['message'],
                             exc_info=False
                             )

        elif request_method == 'DELETE':
            try:
                r = requests.request(request_method,
                                     url=url,
                                     headers=self.headers)
                logger.debug(f'{request_method} to {url} '
                             f'with headers {self.headers}.'
                             )
                r.raise_for_status()
                return r.status_code
            except requests.exceptions.HTTPError:
                logger.error(r.json()['message'],
                             exc_info=False
                             )
