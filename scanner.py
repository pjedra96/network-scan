from tkinter import *
from tkinter import ttk
from sys import platform
from datetime import datetime
import uuid
import nmap
import urllib.request as urllib2
import socket
import netifaces
import pyperclip

window = Tk()
window.title('Py Local Network Scanner')
window.geometry('970x400')
window.resizable('False', 'False')
local_IP = 0

# frame
game_frame = Frame(window, width=1000, height=400,borderwidth = 0, highlightthickness = 0)
game_frame.place(x = 0, y = 0)

# copy from a specific cell from the treeview table to a clipboard
def copy_from_treeview(tree, event):
    selection = tree.selection()
    column = tree.identify_column(event.x)
    column_no = int(column.replace("#", "")) - 1
            
    copy_values = []
    for each in selection:
        try:
            value = tree.item(each)["values"][column_no]
            copy_values.append(str(value))
        except:
            pass
        
    copy_string = "\n".join(copy_values)
    pyperclip.copy(copy_string)

# function to start the host scan in the local network
def scan():
	start_scan['state'] = DISABLED

	clear_table()
	display_hosts(scan_network(get_ip()))
	start_scan['state'] = NORMAL
	

start_scan = Button(game_frame, text='Scan Network', state='normal', command=scan)
start_scan.place(x = 10, y = 4)

table = ttk.Treeview(game_frame, height=380)
table.place(x=0, y=33)
table.bind("<Control-Key-c>", lambda x: copy_from_treeview(table, x))

def clear_table():
	for item in table.get_children():
		table.delete(item)

clear_table_btn = Button(game_frame, text='Cls', state='normal', command=clear_table)
clear_table_btn.place(x = 100, y = 4)

hosts = []

def draw_table():
	#table
	table['columns'] = ('ip_address', 'hostname', 'mac_address', 'adapter_company', 'device_info', 'detected', 'active')
	table.column("#0", width=0,  stretch=NO)
	table.column("ip_address",anchor=CENTER, width=118)
	table.column("hostname",anchor=CENTER,width=110)
	table.column("mac_address",anchor=CENTER,width=140)
	table.column("adapter_company",anchor=CENTER,width=220)
	table.column("device_info",anchor=CENTER,width=149)
	table.column("detected",anchor=CENTER,width=140)
	table.column("active",anchor=CENTER,width=90)

	table.heading("#0",text="",anchor=CENTER)
	table.heading("ip_address",text="IP_address",anchor=CENTER)
	table.heading("hostname",text="Hostname",anchor=CENTER)
	table.heading("mac_address",text="MAC Address",anchor=CENTER)
	table.heading("adapter_company",text="Adapter Company",anchor=CENTER)
	table.heading("device_info",text="Device Info",anchor=CENTER)
	table.heading("detected",text="Date Detected",anchor=CENTER)
	table.heading("active",text="Is active",anchor=CENTER)

# gets local mac address
def get_mac():
	return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1]).upper()

# finds the vendor name by the mac address
def resolveMac(mac):
    try:
        url = "https://api.macvendors.com/"
        request = urllib2.Request(url + mac, headers={'User-Agent': "API Browser"})
        response = urllib2.urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
        vendor = vendor[:25]
        return vendor
    except:
        return "N/A"

# scans the network for available hosts
def scan_network(ip_address):
	global hosts
	hosts = []
	default_gateway_address = netifaces.gateways()['default'][netifaces.AF_INET][0]

	nm = nmap.PortScanner()
	# if linux run the scan function with sudo
	if platform == "linux" or platform == "linux2":
		nm.scan(ip_address, arguments='-sP', sudo=True)
	else:
		nm.scan(ip_address, arguments='-sP', sudo=False)
		# -R

	for ip in nm.all_hosts():
		host = nm[ip]

		mac = "-"
		vendorName = "-"
		date_detected = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
		machine_hostname = "-"

		if 'ipv4' in host['addresses']:
			if 'mac' in host['addresses']:
				mac = host['addresses']['mac']
				if mac in host['vendor']:
					vendorName = host['vendor'][mac]

			status = host['status']['state']

			# look for a localhost
			if ip == default_gateway_address:
				device_info = 'Your router'
			elif ip == local_IP:
				mac = get_mac()
				vendorName = resolveMac(mac)
				machine_hostname = socket.gethostname()
				device_info = 'Your computer'
			else:
				device_info = '-'

			rHost = {'ip': ip, 'hostname': machine_hostname, 'mac': mac, 'device_info': device_info, 'vendor': vendorName, 'status': status, 'date_detected': date_detected}

			hosts.append(rHost)

# get the ip address of the LAN to scan
def get_ip():
	global local_IP

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(0)
	try:
		# doesn't even have to be reachable
		s.connect(('10.254.254.254', 1))
		IP = s.getsockname()[0]
	except Exception:
		IP = '127.0.0.1'
	finally:
		s.close()
		local_IP = IP
		IP = IP[:IP.rfind('.')+1] + '1' + '/24' # turn the localhost ip into a local network address
		return IP

def gethostname_by_ip(ip):
	try:
		return socket.gethostbyaddr(ip)[0]
	except socket.herror:
		return '-'

def display_hosts(data):
	global hosts, table
	## add data
	index_val = 0

	for host in hosts:
		table.insert(parent='',index='end',iid=index_val,text='',values=(host['ip'], host['hostname'], host['mac'], host['vendor'], host['device_info'],host['date_detected'], host['status']))
		index_val +=1

if __name__ == "__main__":
	draw_table()
	display_hosts(scan_network(get_ip()))
	window.mainloop()