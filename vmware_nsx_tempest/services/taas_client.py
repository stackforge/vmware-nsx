from oslo_log import log

from tempest.lib.services.network import base

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest._i18n import _LW
from vmware_nsx_tempest.common import constants

LOG = log.getLogger(__name__)


class TaaSClient(base.BaseNetworkClient):
    """
    Request resources via API for TapService and TapFlow 
         create request
         show request
         delete request
         list all request
    """

# Tap Service 

    def create_ts(self, **kwargs):
        uri = '/taas/tap_services'
        post_data = {'tap_service': kwargs}
        LOG.info(_LI("URI : %(uri)s, posting data : %(post_data)s") % {
            "uri": uri, "post_data": post_data})
        return self.create_resource(uri, post_data)

    def list_ts(self, **filters):
        uri = '/taas/tap_services' 
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.list_resources(uri, **filters)

    def show_ts(self, ts_id, **fields):
        uri = '/taas/tap_services' + "/" + ts_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.show_resource(uri, **fields)

    def delete_ts(self, ts_id):
        uri = '/taas/tap_services' + "/" + ts_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.delete_resource(uri)

#  Tap Flow 

    def create_tf(self, **kwargs):
        uri = '/taas/tap_flows'
        post_data = {'tap_flow': kwargs}
        LOG.info(_LI("URI : %(uri)s, posting data : %(post_data)s") % {
            "uri": uri, "post_data": post_data})
        return self.create_resource(uri, post_data)

    def list_tf(self, **filters):
        uri = '/taas/tap_flows'
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.list_resources(uri, **filters)

    def show_tf(self, tf_id, **fields):
        uri = '/taas/tap_flows' + "/" + tf_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.show_resource(uri, **fields)

    def delete_tf(self, tf_id):
        uri = '/taas/tap_flows' + "/" + tf_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.delete_resource(uri)



def get_client(client_mgr):

    """
    Create a l2-gateway client from manager or networks_client
    """
    LOG.debug("coming from get client ") 
    try:
        manager = getattr(client_mgr, "manager", client_mgr)
        net_client = getattr(manager, "networks_client")
        _params = manager.default_params_with_timeout_values.copy()
    except AttributeError as attribute_err:
        LOG.warning(_LW("Failed to locate the attribute, Error: %(err_msg)s") %
                    {"err_msg": attribute_err.__str__()})
        _params = {}
    client = TaaSClient(net_client.auth_provider,
                             net_client.service,
                             net_client.region,
                             net_client.endpoint_type,
                             **_params)
    return client
