
import time

from tempest.common import waiters


def wait_until_servers_become_active(server_id_list, servers_client,
                                     timeout=600, interval=5.0):
    for server_id in server_id_list:
        waiters.wait_for_server_status(
            client=servers_client,
            server_id=server['id'], status='ACTIVE')


def delete_tenant_servers(servers_client, trys=5):
    # try at least trys+1 time to delete servers, otherwise
    # network resources can not be deleted
    for s in servers_client.list_servers()['servers']:
        servers_client.delete_server(s['id'])
    for x in range(0, trys):
        try:
            waitfor_servers_terminated(servers_client)
            return
        except Exception:
            pass
    # last try
    waitfor_servers_terminated(servers_client)


def waitfor_servers_terminated(servers_client, pause=2.0):
    while (True):
        s_list = servers_client.list_servers()['servers']
        if len(s_list) < 1:
            return
        time.sleep(pause)
