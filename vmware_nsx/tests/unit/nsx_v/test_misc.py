# Copyright (c) 2014 VMware.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import mock
import tenacity

from neutron.tests import base

from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.plugins.nsx_v.vshield import vcns


def raise_until_attempt(attempt, exception):
    def raises_until():
        if raises_until.current_attempt < attempt:
            raises_until.current_attempt += 1
            raise exception
        else:
            return raises_until.current_attempt
    raises_until.current_attempt = 1
    return raises_until


#Mock for the tenacity retrying sleeping method
@contextlib.contextmanager
def mock_retrying_sleep():
    class _MockRetrying(tenacity.Retrying):
        def __init__(self, *args, **kwargs):
            super(_MockRetrying, self).__init__(*args, **kwargs)
            self.sleep = self._mock_sleep
            self.sleeps = []

        def _mock_sleep(self, secs):
            self.sleeps.append(secs)

        def __call__(self, *args, **kwargs):
            self.__init__(*args, **kwargs)
            return self

    with mock.patch.object(tenacity, 'Retrying',
                           new_callable=_MockRetrying) as mock_retrying:
        yield mock_retrying


class TestMisc(base.BaseTestCase):
    response = """
        <error><details>Dummy</details><errorCode>1</errorCode>
        <moduleName>core-services</moduleName></error>
        """

    def test_retry_on_exception_one_attempt(self):
        success_on_first_attempt = raise_until_attempt(
            1, exceptions.RequestBad(uri='', response=''))
        should_return_one = vcns.retry_upon_exception(
            exceptions.RequestBad,
            max_attempts=1)(success_on_first_attempt)
        self.assertEqual(1, should_return_one())

    def test_retry_on_exception_five_attempts(self):
        success_on_fifth_attempt = raise_until_attempt(
            5, exceptions.RequestBad(uri='', response=''))
        with mock_retrying_sleep():
            should_return_five = vcns.retry_upon_exception(
                exceptions.RequestBad,
                max_attempts=10)(success_on_fifth_attempt)
            self.assertEqual(5, should_return_five())

    def test_retry_on_exception_exceed_attempts(self):
        success_on_fifth_attempt = raise_until_attempt(
            5, exceptions.RequestBad(uri='', response=''))
        with mock_retrying_sleep():
            should_raise = vcns.retry_upon_exception(
                exceptions.RequestBad,
                max_attempts=4)(success_on_fifth_attempt)
            self.assertRaises(tenacity.RetryError, should_raise)

    def test_retry_on_exception_exclude_error_codes_retry(self):
        success_on_fifth_attempt = raise_until_attempt(
            5, exceptions.RequestBad(uri='', response=self.response))
        with mock_retrying_sleep():
            # excluding another error code, so should retry
            should_return_five = vcns.retry_upon_exception_exclude_error_codes(
                exceptions.RequestBad, [2],
                max_attempts=10)(success_on_fifth_attempt)
            self.assertEqual(5, should_return_five())

    def test_retry_on_exception_exclude_error_codes_raise(self):
        success_on_fifth_attempt = raise_until_attempt(
            5, exceptions.RequestBad(uri='', response=self.response))
        # excluding the returned error code, so no retries are expected
        should_raise = vcns.retry_upon_exception_exclude_error_codes(
            exceptions.RequestBad, [1],
            max_attempts=10)(success_on_fifth_attempt)
        self.assertRaises(exceptions.RequestBad, should_raise)
