# plugin.sh - Devstack extras dispatch script

dir=${GITDIR['vmware-nsx']}/devstack

if [[ $Q_PLUGIN == 'vmware_nsx_v' ]]; then
    source $dir/vmware_nsx_v
else
    source $dir/vmware_nsx
fi
