from lab_app import *
import errno
import json
from multiprocessing import Process

from random import randrange


def setup_snort(h_if):
    print("Setting up SNORT environment")
    try:
        ns_root.shutdown()
    except:
        print('[*] Did not shutdown cleanly, trying again')
        docker_clean()
    finally:
        docker_clean()
  # Create ids node
    image = '34334:ids'
    name = 'snort'
    if not c(name):
        ns_root.register_ns(name, image)
    nic = c(name).connect(ns_root)
    c(name).enter_ns()
    r('ip link set $nic up')
  # Create internet node
    image = '34334/labs:inet'
    name = 'inet'
    if not c(name):
        ns_root.register_ns(name, image)
    nic1 = c(name).connect(ns_root)
    nic2 = c(name).connect(c('snort'))
    c(name).enter_ns()
    r('ip link set $nic1 up')
    r('ip link set $nic2 up')
    


    ns_root.enter_ns()
    r('service NetworkManager stop')
    r('ip link set $nic name 34334_lab')
    r('dhclient -v 34334_lab')   
    dfgw_set = False
    
    new_gw = setup_inet('inet', h_if, '172.0.0.0/24')
    

def setup_network_routing(h_if):
    try:
        ns_root.shutdown()
    except:
        print('[*] Did not shutdown cleanly, trying again')
        docker_clean()
    finally:
        docker_clean()

    net = { 'nodes' : [{'router' : ['router1','router2','router3','router4']},
                                     {'switch' : ['sw']},
                                     {'base'   : ['host1','host2','host3','host4']}
                                    ]}
    for nodetypes in net['nodes']:
        for nodetype in nodetypes.keys():
            image = '34334:'+nodetype
            for node in nodetypes[nodetype]:
                print("Establish "+ node +" of type "+nodetype)
                if not c(node):
                    ns_root.register_ns(node, image)

    connect_router(1,2,'1_2')
    connect_router(2,4,'2_4')
    connect_router(4,3,'3_4')
    connect_router(3,1,'1_3')
  
  
  # Connecting hosts to routers
    for i in range(4):
        k = str(i+1)
        name = 'host' + k
        rname = 'router%s' % k
        nic = c(name).connect(c(rname))
        r('ip netns exec '+name+' ip link set '+nic+' name h_'+k) 
        r('ip netns exec '+rname+' ip link set '+nic+' name h_'+k) 
        r('ip netns exec '+name+' ip addr add 192.168.'+k+'.1'+k+'/24 dev h_'+k)
        r('ip netns exec '+name+' ip link set h_'+k+' up')
        r('ip netns exec '+rname+' ip link set h_'+k+' up')
        r('ip netns exec %s route add default gw 192.168.%s.%s' % (name,k,k))
    
    #Adding bridge in switch
    c('sw').enter_ns()
    r('brctl addbr br0')    
    r('ip link set br0 up')
    
    #Connecting switch to router 1 and router 4
    name = 'sw'
    rname = 'router1'
    interface = 'r_1'
    rinterface = 'r_1_4'
    iprouter = '10.1.4.1/24'
    nic = c(name).connect(c(rname))
    r('ip netns exec '+name+' ip link set '+nic+' name '+interface) 
    r('ip netns exec '+rname+' ip link set '+nic+' name '+rinterface) 
    #r('ip netns exec '+rname+' ip addr add '+iprouter+' dev '+rinterface)
    r('ip netns exec '+name+' ip link set '+interface+' up')
    r('ip netns exec '+rname+' ip link set '+rinterface+' up')
    r('ip netns exec '+name+' brctl addif br0 $interface')

    name = 'sw'
    rname = 'router4'
    interface = 'r_4'
    rinterface = 'r_1_4'
    iprouter = '10.1.4.4/24'
    nic = c(name).connect(c(rname))
    r('ip netns exec '+name+' ip link set '+nic+' name '+interface) 
    r('ip netns exec '+rname+' ip link set '+nic+' name '+rinterface) 
    #r('ip netns exec '+rname+' ip addr add '+iprouter+' dev '+rinterface)
    r('ip netns exec '+name+' ip link set '+interface+' up')
    r('ip netns exec '+rname+' ip link set '+rinterface+' up')
    r('ip netns exec '+name+' brctl addif br0 $interface')
    
        
    #Connecting kali to router 1
    nic = c('router1').connect(ns_root)
    
    # Select config file and start service in router 1 and 2
    for i in range(2):
        k=str(i+1)
        r('docker exec -ti router%s mv /etc/quagga/ripd%s.conf /etc/quagga/ripd.conf' % (k,k))
        r('docker exec -ti router%s mv /etc/quagga/zebra%s.conf /etc/quagga/zebra.conf' % (k,k))
        r('docker exec -ti router%s service quagga start' % k)




 
   # Start SSH service in each router
    for i in range(4):
        r('docker exec router%s service ssh start' % str(i+1)) 

  

  #new_gw = setup_inet('inet', h_if, net_1['subnet'])
  #we are going to assume we are only dealing with one hub
  #yes....this is gross, maybe make a convenience function
  #this gets 'sw1' for example in net_1
    #sw1 = [net_1['hubs'][0][x] for x in net_2['hubs'][0].keys() if x != 'clients'][0][0]
    #sw2 = [net_2['hubs'][0][x] for x in net_2['hubs'][0].keys() if x != 'clients'][0][0]

    #here we fixup dns by adding the other dns servers ip to /etc/resolv.conf
    #or dns in ['sw1', 'sw2']:
    #    for dns2 in (sw1,sw2):
    #        if dns != dns2:
          #should only have one ip.....
        #        print (dns + "  " + str(c(dns))) 
        #        nic,ip = next(c(dns).get_ips()).popitem()
            #    echo = 'echo nameserver %s >> /etc/resolv.conf' % ip
            #add the other nameserver to resolv.conf
            #we are using subprocess here as we have a complicated command, " and ' abound
                #subprocess.check_call(['docker', 'exec', dns, 'bash', '-c', echo])
        #setup inet, just making sure we are in the root ns
    ns_root.enter_ns()
    #rename our interface and move it into inet
    #r('ip link set $h_if down')
    #r('ip link set $h_if name root')
    #r('ip link set root netns inet')

    #connect host to sw1 - hardcoding is bad
    
    #dropping in to ns to attach interface to bridge
    
    
    

    ########################### 
    ns_root.enter_ns()

    #ensure network manager doesn't mess with anything
    r('service NetworkManager stop')
    r('ip link set $nic name 34334_lab')
    #p = Process(target=r, args=('dhclient -v w4sp_lab',))
    #p.start()

    ###r('ip netns exec router3 ip link set router3_0 up')
    ###r('ip netns exec router1 ip link set router1_1 up')
    #r('ip netns exec router3 ip addr add 192.168.250.1/24 dev router3_0')
    #r('ip netns exec router1 ip addr add 192.168.250.2/24 dev router1_1')

    ###r('ip netns exec router1 ip link set router1_0 up')
    #r('ip netns exec router1 ip addr add 192.168.100.1/24 dev router1_0')

    #r('ip netns exec router1 dhclient -v router1_0')

    #r('dhclient -v 34334_lab')
    
    #c('inet').enter_ns()
    ###############################################
     
    #add the routes to the other network
    #hardcoding since I am lazy
    #other_net = net_1['subnet'].strip('/24')
    #other_gw = net_2['subnet'].strip('0/24') + '1'

    dfgw_set = False

    #while not dfgw_set:
    #    for ips in c('inet').get_ips():
     #       if 'inet_0' in ips.keys():
      #          #r('route add -net $other_net netmask 255.255.255.0 gw $other_gw')
       #         dfgw_set = True
        
    #############################################
    #c('inet').exit_ns()

    """
    try:
        r('ping -c 2 192.100.200.1')
    except:
        print('[*] Bad network generated, start over')
        setup_network2(h_if)
    """
def read_setup(setup):
    f = open('networks/'+setup+'.json')
    data = json.load(f)
    return (data.get("nodes"),data.get("bridges"))

def create_nodes(nodes):
    for node in nodes:
        if not c(node['name']):
            ns_root.register_ns(node['name'],node['image'])
            
def create_bridges(bridges):  
    for bridge in bridges:
        # If 2 adjacencies it is basically a link
        adj = bridge['adjacencies']
        print(adj)
        adjcount = len(adj)
        if adjcount==2:
            rname = adj.pop()
            name = adj.pop()
            print("Connecting " +name + " to " + rname)
            nic = c(name).connect(c(rname))
            r('ip netns exec $name ip link set $nic up')
            r('ip netns exec $rname ip link set $name up')
        if adjcount > 2:
            # Create switch
            print("Setting up bridge for 3 or more nodes")
            print(adj)
            bname = bridge['name']
            ns_root.register_ns(bname, '34334:switch','switch')
            c(bname).enter_ns()
            # Adding bridge in ns
            r('brctl addbr $bname')
            # or r('ip link add name $bname type bridge')
            r('ip link set $bname up')
            r('brctl stp $bname off')
            r('brctl setageing $bname 0')
            r('brctl setfd $bname 0')
            c(bname).exit_ns()
            for name in adj:
                nic = c(bname).connect(c(name))      
                r('ip netns exec $bname ip link set $name up')
                r('ip netns exec $name ip link set $bname up') 
                r('ip netns exec $bname brctl addif $bname $name')
                
def ip_address(iprange,host):
    prefix = '.'.join(iprange.split('.')[0:3])
    print(prefix)
    ipaddress = prefix + "." + str(host)
    print(ipaddress)
    return ipaddress
            
def set_addresses(bridges):
    # Setting addresses based on json. We assume /24 prefixes and use first available value for gateway
    for bridge in bridges:
        bname = bridge['name']
        adj = bridge['adjacencies']
        hostid = 1
        try:
            gw = bridge['gateway']
            gwip = ip_address(bridge['network'],hostid)
            ip = gwip + "/24"
            r('ip netns exec internet ip addr add $ip dev $bname')
            hostid = hostid +1
            adj.remove(gw)
        except:
            gw = ''
        for name in adj:
            ip = ip_address(bridge['network'],hostid)+"/24"
            r('ip netns exec $name ip addr add $ip dev $bname')
            hostid = hostid + 1
            if gw != '':
                r('ip netns exec $name route add default gw $gwip')

def set_internet(inetnode, interface, bridge, ip, gw):
    # Moving external connection to interface in docker config.
    nic = c(bridge).connect(ns_root)
    print("Nic name: "+ nic)
    #ensure network manager doesn't mess with anything
    r('ip netns exec $bridge brctl addif $bridge $nic')
    r('ip netns exec $bridge ip link set $nic up')
    ns_root.enter_ns()

    r('service NetworkManager stop')
    # Connecting root to lab
    r('ip link set $bridge name 34334_lab')
    r('ip link set 34334_lab up')
    r('ip addr add $ip dev 34334_lab')
    # Moving external interface to defined lab node
    r('ip link set $interface netns $inetnode')
    r('route add default gw $gw')
    
    
    c(inetnode).enter_ns()
    inet_nic = bridge
    r('ip link set $interface up')
    # Setting up NAT as inet node
    r('dhclient $interface')
    r('iptables -t nat -A POSTROUTING -o $interface -j MASQUERADE')
    r('iptables -A FORWARD -i $interface -o $inet_nic -m state --state RELATED,ESTABLISHED -j ACCEPT')
    r('iptables -A FORWARD -i $inet_nic -o $interface -j ACCEPT')
    
            
                
def setup_firewall(h_if):
    try:
        ns_root.shutdown()
    except:
        print('[*] Did not shutdown cleanly, trying again')
        docker_clean()
    finally:
        docker_clean()
        # Stop IP forwarding on Debian
        r('sysctl -w net.ipv4.ip_forward=0')    
        # Reading network setup
        (nodes,bridges) = read_setup("firewall")
        # Create containers
        create_nodes(nodes)
        # Connecting all dockers in bridges
        create_bridges(bridges)
        set_addresses(bridges)  
        # Connecting to internet via lab. Pretty much hardcoded          
        set_internet('internet',h_if,'internal','192.168.1.100/24','192.168.1.1')

   
def setup_network(h_if):

    #docker_clean()

    #the key is the image name
    #net1 = {'sw' : ['sw1'], 'vrrpd' : ['r1', 'r2'],
    #    'base' : ['vic', 'attacker']}

    #net2 = {'sw' : ['sw2'], 'vrrpd' : ['r1', 'r2'],
    #     'base' : ['inet']}

  
    net_1 = {'subnet' : '192.100.200.0/24', 
                'hubs' : [ 
                    {'switch' : ['sw1'], 
                        'clients' : [
                            {'vrrpd' : ['r1', 'r2']}, 
                            {'victims' : ['vic1', 'vic2', 'vic3']}
                        ]
                    }
                ]
            }
  
    net_2 = {'subnet' : '10.100.200.0/24', 
                'hubs' : [ 
                    {'switch' : ['sw2'], 
                        'clients' : [
                            {'vrrpd' : ['r1', 'r2']}, 
                            {'base' : ['inet']},
                            {'victims' : ['vic4', 'vic5']}
                        ]
                    }
                ]
            }


    net_3 = {'subnet' : '10.1.1.0/24',
                'hubs' : [ 
                    {'sw' : ['sw3'],
                        'clients' : [
                            {'base' : ['vic6', 'vic7', 'inet']},
                            {'vrrpd' : ['r3', 'r4']}

                         ]
                     }
                ]
            }

    create_net(net_1)
    create_net(net_2)
    #create_net(net_3)    
 
    #hardcoding this for now...I know these are the machines I want to run vrrp
    setup_vrrp(['r1', 'r2'])

    new_gw = setup_inet('inet', h_if, net_1['subnet'])

    #now it is time to setup routes
    #hardcoding this logic for now :(
    for router in ['r1', 'r2']:
       
        c(router).enter_ns()
        #######################################
 
        r('ip route add default via $new_gw')
    
        for nic in c(router).nics:
            #we are going to add an artificial delay here
            #add 1ms delay with a 5ms jitter
            r('tc qdisc add dev $nic root netem delay 1ms 5ms')
    
        ########################################
        c(router).exit_ns()
 
    #hardcoding is bad mmmkay
    switches = ['sw1', 'sw2']
    for dns in switches:
        for dns2 in switches:
            if dns != dns2:
                #should only have one ip.....
                nic,ip = next(c(dns2).get_ips()).popitem()
                echo = 'echo nameserver %s >> /etc/resolv.conf' % ip
                #add the other nameserver to resolv.conf
                #we are using subprocess here as we have a complicated command, " and ' abound
                subprocess.check_call(['docker', 'exec', dns, 'bash', '-c', echo])

        #add the upstream google dns and localhost server
        subprocess.check_call(['docker', 'exec', dns, 'bash', '-c', 'echo nameserver 8.8.8.8 >> /etc/resolv.conf'])

    #connect host to sw1 - hardcoding is bad
    nic = c('sw1').connect(ns_root)
    #dropping in to ns to attach interface to bridge
    c('sw1').enter_ns()
    ###########################

    r('brctl addif br0 $nic')
    r('ip link set $nic up')

    ########################### 
    ns_root.enter_ns()

    #ensure network manager doesn't mess with anything
    r('service network-manager stop')
    r('ip link set $nic name 34334_lab')
    r('dhclient -v 34334_lab')    


