class FirewallSection(BaseResource):

    CONSTANT = 'firewall section'
    API_VERSION = '4.0'

    @staticmethod
    def read_endpoint():
        return '/firewall/globalroot-0/config'

    @staticmethod
    def delete_endpoint():
        return '/firewall/globalroot-0/config/layer3sections/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['id']

    @staticmethod
    def process_response(response):
        l3_sections = response.json()['layer3Sections']['layer3Sections']
        firewall_sections = [s for s in l3_sections if s['name'] !=
                             "Default Section Layer3"]
        return firewall_sections

    @staticmethod
    def process_db_response(response):
        pass


class SecurityGroup(BaseResource):

    CONSTANT = 'security group'
    API_VERSION = '2.0'

    @staticmethod
    def read_endpoint():
        return '/services/securitygroup/scope/globalroot-0'

    @staticmethod
    def delete_endpoint():
        return '/services/securitygroup/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['objectId']

    @staticmethod
    def process_response(response):
        sg_all = response.json()
        # Remove Activity Monitoring Data Collection, which is not
        # related to any security group created by OpenStack
        security_groups = [sg for sg in sg_all if
                           sg['name'] != "Activity Monitoring Data Collection"]
        return security_groups
    
    @staticmethod
    def process_db_response(response):
        pass


class SpoofguardPolicies(BaseResource):

    CONSTANT = 'spoofguard policies'
    API_VERSION = '4.0'

    @staticmethod
    def read_endpoint():
        return '/services/spoofguard/policies/'

    @staticmethod
    def delete_endpoint():
        return '/services/spoofguard/policies/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['policyId']

    @staticmethod
    def process_response(response):
        sgp_all = response.json()
        policies = [sgp for sgp in sgp_all['policies'] if
                    sgp['name'] != 'Default Policy']
        return policies
    
    @staticmethod
    def process_db_response(response):
        pass


class Edge(BaseResource):
    
    CONSTANT = 'edge'
    API_VERSION = '4.0'

    @staticmethod
    def read_endpoint():
        return '/edges'

    @staticmethod
    def delete_endpoint():
        return '/edges/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['id']

    @staticmethod
    def process_response(response):
        edges = []
        paging_info = response.json()['edgePage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        total_count = int(paging_info['totalCount'])
        print "There are total %s edges and page size is %s" % (
            total_count, page_size)
        pages = 0 if page_size == 0 else int(math.ceil(float(total_count) / page_size))
        print "Total pages: %s" % pages
        for i in range(0, pages):
            start_index = page_size * i
            params = {'startindex': start_index}
            response = self.get(params=params)
            temp_edges = response.json()['edgePage']['data']
            edges += temp_edges
        return edges
    
    @staticmethod
    def process_db_response(response):
        pass


class LogicalSwitch(BaseResource):

    CONSTANT = 'logical switch'
    API_VERSION = '2.0'
    
    @staticmethod
    def read_endpoint():
        vdn_scope_id = Util.get_vdn_scope_id()
        return '/vdn/scopes/%s/virtualwires' % (vdn_scope_id)

    @staticmethod
    def delete_endpoint():
        return '/vdn/virtualwires/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['objectId']

    @staticmethod
    def process_response(response):
        lswitches = []
        paging_info = response.json()['dataPage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        total_count = int(paging_info['totalCount'])
        print "There are total %s logical switches and page size is %s" % ( 
              total_count, page_size)
        pages = 0 if page_size == 0 else int(math.ceil(float(total_count) / page_size))
        print "Total pages: %s" % pages
        for i in range(0, pages):
            start_index = page_size * i 
            params = {'startindex': start_index}
            response = self.get(params=params)
            temp_lswitches = response.json()['dataPage']['data']
            lswitches += temp_lswitches
        return lswitches
    
    @staticmethod
    def process_db_response(response):
        pass


class Util(object):
    @staticmethod
    def get_vdn_scope_id():
        """
        Retrieve existing network scope id
        """

        vsm_client.set_api_version('2.0');
        vsm_client.set_endpoint("/vdn/scopes")
        response = vsm_client.get();
        if len(response.json()['allScopes']) == 0:
            return
        else:
            return response.json()['allScopes'][0]['objectId']

   

