#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

"""Router extensions action implementations"""

from openstackclient.network.v2 import router

from vmware_nsx._i18n import _
from vmware_nsx.extensions import routersize
from vmware_nsx.extensions import routertype


def add_router_size_to_parser(parser):
        parser.add_argument(
            '--router-size',
            metavar='<router-size>',
            choices=routersize.VALID_EDGE_SIZES,
            help=_("Router Size")
        )


def add_router_type_to_parser(parser):
    parser.add_argument(
        '--router-type',
        metavar='<router-type>',
        choices=routertype.VALID_TYPES,
        help=_("Router Type")
    )


class NsxCreateRouter(router.CreateRouter):
    """Create a new router with vmware nsx extensions """

    def get_parser(self, prog_name):
        parser = super(NsxCreateRouter, self).get_parser(prog_name)

        #DEBUG ADIT - do this for nsxv only
        add_router_size_to_parser(parser)
        add_router_type_to_parser(parser)
        return parser


class NsxSetRouter(router.SetRouter):
    """Set router properties"""

    def get_parser(self, prog_name):
        parser = super(NsxSetRouter, self).get_parser(prog_name)

        #DEBUG ADIT - do this for nsxv only
        add_router_size_to_parser(parser)
        add_router_type_to_parser(parser)
        return parser
