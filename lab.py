from lab_app import *
import errno
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

    net_1 = {'subnet' : '192.168.100.0/24',
                'hubs' : [
		    {'switch' : ['sw1'],
			'clients' : [ {'router' : ['router1']}  ]
                 }]                   
            }

    net_2 = {'subnet' : '10.1.4.0/24',
                'hubs' : [
                    {'switch' : ['sw2'],
                        'clients' : [
                            {'router' : ['router1']}, {'router' : ['router4']}
                        ]
                    }
                ]
            }


    create_netx(net_1)
    create_netx(net_2) 
    
    ###r('ip netns exec router1 ip link set router1_1 name router1_14')
    ###r('ip netns exec router1 ip link set router1_14 up')

    ###r('ip netns exec router4 ip link set router4_0 name router4_11')
    ###r('ip netns exec router4 ip link set router4_11 up')



    image = '34334/labs:router'
    name = 'router2'
    if not c(name):
      ns_root.register_ns(name, image)

    name = 'router3'
    if not c(name):
      ns_root.register_ns(name, image)


    connect_router(1,2,'1_2')
    connect_router(2,4,'2_4')
    connect_router(4,3,'3_4')
    connect_router(3,1,'1_3')
  
  # Select config file and start service in router 1 and 2
    for i in range(2):
      k=str(i+1)
      r('docker exec -ti router%s sudo mv /etc/quagga/ripd%s.conf /etc/quagga/ripd.conf' % (k,k))
      r('docker exec -ti router%s sudo mv /etc/quagga/zebra%s.conf /etc/quagga/zebra.conf' % (k,k))
      r('docker exec -ti router%s sudo service quagga start' % k)

   

    # Creating hosts as base images and connect
    image = '34334/labs:base'
    for i in range(4):
      k = str(i+1)
      name = 'host' + k
      if not c(name):
        ns_root.register_ns(name, image)
        rname = 'router%s' % k
        nic = c(name).connect(c(rname))
        r('ip netns exec '+name+' ip link set '+nic+' name h_'+k) 
        r('ip netns exec '+rname+' ip link set '+nic+' name h_'+k) 
        r('ip netns exec '+name+' ip addr add 192.168.'+k+'.1'+k+'/24 dev h_'+k)
        r('ip netns exec '+name+' ip link set h_'+k+' up')
        r('ip netns exec '+rname+' ip link set h_'+k+' up')
        r('ip netns exec %s route add default gw 192.168.%s.%s' % (name,k,k))

 
    # Start SSH service in each router
    for i in range(4):
      r('docker exec router%s service ssh start' % str(i+1)) 

  

    #new_gw = setup_inet('inet', h_if, net_1['subnet'])

    #we are going to assume we are only dealing with one hub
    #yes....this is gross, maybe make a convenience function
    #this gets 'sw1' for example in net_1
    sw1 = [net_1['hubs'][0][x] for x in net_2['hubs'][0].keys() if x != 'clients'][0][0]

    sw2 = [net_2['hubs'][0][x] for x in net_2['hubs'][0].keys() if x != 'clients'][0][0]

    #here we fixup dns by adding the other dns servers ip to /etc/resolv.conf
    for dns in ['sw1', 'sw2']:
        for dns2 in (sw1,sw2):
            if dns != dns2:
                #should only have one ip.....
                print (dns + "  " + str(c(dns))) 
                nic,ip = next(c(dns).get_ips()).popitem()
                echo = 'echo nameserver %s >> /etc/resolv.conf' % ip
                #add the other nameserver to resolv.conf
                #we are using subprocess here as we have a complicated command, " and ' abound
                subprocess.check_call(['docker', 'exec', dns, 'bash', '-c', echo])

    #setup inet, just making sure we are in the root ns
    ns_root.enter_ns()
    #rename our interface and move it into inet
    #r('ip link set $h_if down')
    #r('ip link set $h_if name root')
    #r('ip link set root netns inet')

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

    r('ip netns exec router1 dhclient -v router1_0')

    r('dhclient -v 34334_lab')
    
    #c('inet').enter_ns()
    ###############################################
     
    #add the routes to the other network
    #hardcoding since I am lazy
    other_net = net_1['subnet'].strip('/24')
    other_gw = net_2['subnet'].strip('0/24') + '1'

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


def setup_firewall(h_if):
	try:
		ns_root.shutdown()
	except:
		print('[*] Did not shutdown cleanly, trying again')
		docker_clean()
	finally:
		docker_clean()
#
		# Create containers
		if not c('server'):
			ns_root.register_ns('server','34334:victims')   
		if not c('internet'):
			ns_root.register_ns('internet','34334:inet')   
		if not c('snort'):
			ns_root.register_ns('snort','34334:ids') 
		if not c('switch'):
			ns_root.register_ns('sw','34334:switch')
		
		# Connect bridge to snort, server and internet
		c('sw').enter_ns()
		r('brctl addbr br0')
		r('ip link set br0 up')
		c('sw').exit_ns()
		for name in (['snort','internet','server']):
			nic = c('sw').connect(c(name))
			r('ip netns exec $name ip link set $nic name lab0')
			r('ip netns exec sw ip link set $nic name '+name+'0')
			r('ip netns exec $name ip link set lab0 up') 
			r('ip netns exec sw ip link set '+name+'0 up')
			r('ip netns exec sw brctl addif br0 '+name+'0')
				
		# Add links from all devices to bridge
		nic = c('sw').connect(ns_root)
		print("Nic name: " + nic)
		#dropping in to ns to attach interface to bridge
		c('sw').enter_ns()
		###########################
		r('brctl addif br0 $nic')
		r('ip link set $nic up')
		r('brctl stp br0 off')
		r('brctl setageing br0 0')
		r('brctl setfd br0 0')
		########################### 

		r('ip netns exec internet ip addr add 192.168.0.1/24 dev lab0')
		r('ip netns exec snort ip addr add 192.168.0.3/24 dev lab0')
		r('ip netns exec server ip addr add 192.168.0.4/24 dev lab0')
		
		for name in (['snort','server']):
			r('ip netns exec $name route add default gw 192.168.0.1')
		
		ns_root.enter_ns()
		#ensure network manager doesn't mess with anything
		r('service NetworkManager stop')
		r('ip link set $nic name 34334_lab')
		r('ip link set 34334_lab up')
		r('ip addr add 192.168.0.2/24 dev 34334_lab')

		r('ip link set $h_if netns internet')
		r('route add default gw 192.168.0.1')

 
		c('internet').enter_ns()
		inet_nic='lab0'
		r('ip link set $h_if up')
		# dhcp client for outgoing interface
		r('ip netns exec internet dhclient $h_if')

		r('iptables -t nat -A POSTROUTING -o $h_if -j MASQUERADE')
		r('iptables -A FORWARD -i $h_if -o $inet_nic -m state --state RELATED,ESTABLISHED -j ACCEPT')
		r('iptables -A FORWARD -i $inet_nic -o $h_if -j ACCEPT')
   
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


