#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# NoSafe Python Bot v1.1 Beta - Coded in priv8/#NOSAFE
# Coded by ins3c7 and Zirou
#
# Coded for Priv8 Server
#
# Thanks hc0d3r, HyOgA, idz, chk_, vL, VitaoDoidao, psycco, PoMeRaNo and all the #NOSAFE family.
#
# Let's Rock! ;D
#
#

import time, os, base64, hashlib, urllib, string
import socket, requests, threading, ftplib
from random import randint

# Necessita instalar:
import paramiko, BeautifulSoup


os.system('clear')

class NoSafe:

	def __init__(self, server, port, nick, name, email, channel, ajoin, admin, prefix, verbose, banner):

		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			self.s.connect((server, port))
		except:
			print 'ERRO: Não foi possível conectar ao HOST: {} e PORTA: {}'.format(str(server),str(port))
			time.sleep(5)
			exit(1)

		time.sleep(0.5)
		self.s.recv(4096)
		self.nick = nick
		self.name = name
		self.email = email
		self.channel = channel
		self.ajoin = ajoin
		self.admin = admin
		self.server = server
		self.prefix = prefix
		self.verbose = verbose
		self.banner = banner

		self.portscan_find = False
		self.data = ''
		self.command = None
		self.close = False

		self.log_dir = os.path.abspath('log')
		if not os.path.exists(self.log_dir):
			os.mkdir(self.log_dir)

		print '\nInicializando...\n'

	def SendCommand(self, cmd):
		comm = cmd + '\r\n'
		self.s.send(comm)

	def SendMsg(self, canal, msg):
		msg = msg + '\r\n'
		self.s.send('PRIVMSG ' + canal + ' ' + msg + '\r\n')

	def SendPingResponse(self):
		if self.data.find('PING') != -1:
			self.SendCommand('PONG ' + self.data.split()[1])

	def Logging(self, canal, nick, message):
		if canal == self.nick:
			canal = nick
		canal = canal.upper()
		f = open('log/'+ canal +'.log', 'a')
		f.write(message +'\n')
		f.close()

	def SendAllChans(self, nick, canal, message):
		try:
			for channel in ajoin:
				self.SendMsg(channel, str(message) + ' ')
			self.SendMsg(canal, self.banner + 'Mensagens enviadas. ')
		except:
			self.SendMsg(canal, self.banner + 'Algo deu errado. ')

	def PortConnect(self, banner, canal, port_host, port_port):
		
		if port_host.find(':') != -1:
			sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
			sock.settimeout(2)
			try:
				host_addr = socket.gethostbyaddr(port_host)[0]
			except:
				host_addr = port_host
			try:
				sock.connect((port_host, port_port))
				self.SendMsg(canal, banner + '0,1[4 PORT 0] IP:15 {}0 DNS:14 {} 0PORTA: 15[{}]4 => 9ABERTA '.format(str(port_host), str(host_addr), str(port_port)))
			except Exception, e:
				self.SendMsg(canal, banner + '0,1[4 PORT 0] IP:15 {}0 DNS:14 {} 0PORTA: 15[{}]4 => FECHADA '.format(str(port_host), str(host_addr), str(port_port)))
				# print str(e)
		else:
			sock = socket.socket()
			sock.settimeout(2)

			try:
				result1 = sock.connect_ex((port_host, port_port))
				try:
					result = socket.getaddrinfo(port_host, port_port, socket.AF_INET6)[0][4][0]
				except:
					result = result1
				try:
					host_addr = socket.gethostbyaddr(port_host)[0]
				except:
					host_addr = port_host
				try:
					host_ip = ''.join(socket.gethostbyaddr(port_host)[2])
				except:
					host_ip = host_addr

				if result == 0:
					self.SendMsg(canal, banner + '0,1[4 PORT 0] IP:15 {}0 DNS:14 {} 0PORTA: 15[{}]4 => 9ABERTA '.format(str(host_ip), str(host_addr), str(port_port)))
				else:
					self.SendMsg(canal, banner + '0,1[4 PORT 0] IP:15 {}0 DNS:14 {} 0PORTA: 15[{}]4 => FECHADA '.format(str(host_ip), str(host_addr), str(port_port)))
			except Exception, e:
				self.SendMsg(canal, banner + '4,1ERRO: ' + str(e))
			

	def SSHConnect(self, banner, canal, ssh_host, ssh_user, ssh_pass):
		self.SendMsg(canal, banner + '0,1[4 SSH 0] Checando 15[{}] '.format(str(ssh_host)))
		self.SendMsg(canal, banner + '0,1[4 SSH 0]15 {}4 => LOGIN: 14[{}]0 SENHA: 14[{}] '.format(str(ssh_host), str(ssh_user), str(ssh_pass)))

		try:
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect(ssh_host, username=ssh_user, password=ssh_pass, timeout=3)
			try:
				stdin, stdout, stderr = ssh.exec_command('uname -a')
				response = stdout.read()
				self.SendMsg(canal, banner + '0,1[4 SSH 0] [14uname0]:4 {} '.format(str(response)))
			except:
				pass

			try:
				stdin, stdout, stderr = ssh.exec_command('id')
				response = stdout.read()
				self.SendMsg(canal, banner + '0,1[4 SSH 0] [14id0]:4 {} '.format(str(response)))
			except:
				pass
			
			try:
				stdin, stdout, stderr = ssh.exec_command('uptime')
				response = stdout.read()
				self.SendMsg(canal, banner + '0,1[4 SSH 0] [14uptime0]:4 {} '.format(str(response)))
			except:
				pass
			
			try:
				stdin, stdout, stderr = ssh.exec_command('date')
				response = stdout.read()
				self.SendMsg(canal, banner + '0,1[4 SSH 0] [14date0]:4 {} '.format(str(response)))
			except:
				pass

			ssh.close()

		except Exception, e:
			self.SendMsg(canal, banner + '0,1[4 SSH 0]15 {} 4=>4 {} '.format(str(ssh_host), str(e)))

	def SSHConnect1(self, banner, canal, ssh_host, ssh_user, ssh_pass):
		# self.SendMsg(canal, banner + '0,5[4SSH0] Checando 4[{}] '.format(str(ssh_host)))

		try:
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect(ssh_host, username=ssh_user, password=ssh_pass, timeout=3)
			
			try:
				stdin, stdout, stderr = ssh.exec_command('uname -a')
				response_uname = stdout.read()
			except:
				pass
			try:
				stdin, stdout2, stderr = ssh.exec_command('id')
				response_id = stdout2.read()
			except:
				pass
			
			ssh.close()

			self.SendMsg(canal, banner + '0,1[4 SSH 0]15 {} 0LOGIN:14 {}0 SENHA:14 {}0 [14uname -a0]:4 {} 0[14id0]:4 {} '.format(str(ssh_host), str(ssh_user), str(ssh_pass), str(response_uname), str(response_id)))

		except Exception, e:
			self.SendMsg(canal, banner + '0,1[4 SSH 0]15 {} 4=> Não foi possível conectar. '.format(str(ssh_host)))
			# self.SendMsg(canal, banner + '0,1[4 SSH 0]15 {} 4=>14 {} '.format(str(ssh_host), str(e)))


	def SSHExec(self, banner, canal, exec_host, exec_user, exec_pass, exec_cmd):
		try:
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect(exec_host, username=exec_user, password=exec_pass, timeout=5)
			try:
				stdin, stdout, stderr = ssh.exec_command(str(exec_cmd))
				response_cmd = stdout.read()
			except:
				pass
			self.SendMsg(canal, banner + '0,1[4 SSH 0]15 {} 0LOGIN:14 {}0 SENHA:14 {}0 [14{}0]:4 {} '.format(str(exec_host), str(exec_user), str(exec_pass), str(exec_cmd), str(response_cmd)))
			ssh.close()
		except Exception, e:
			self.SendMsg(canal, banner + '0,1[4 EXEC 0]15 {} 4=>14 {} '.format(str(exec_host), str(e)))

	def FTPConnect(self, banner, canal, ftp_host, ftp_user, ftp_pass):
		self.SendMsg(canal, banner + '0,1[4 FTP 0] Checando 14[{}] '.format(str(ftp_host)))
		self.SendMsg(canal, banner + '0,1[4 FTP 0] 15{}4 => 0LOGIN: 14[{}]0 SENHA: 14[{}] '.format(str(ftp_host), str(ftp_user), str(ftp_pass)))

		try:
			ftp = ftplib.FTP(ftp_host, timeout=5)
			ftp.login(ftp_user, ftp_pass)
			self.SendMsg(canal, banner + '0,1[4 FTP 0] 15{}4 => 8CONEXÃO ACEITA '.format(str(ftp_host)))
		except Exception, e:
			self.SendMsg(canal, banner + '0,1[4 FTP 0]4 {} '.format(str(e)))

	def PortScan(self, banner, canal, dns_host, dns_port):

		sock = socket.socket()
		sock.settimeout(2)
		port_service = ''
		
		try:
			result = sock.connect_ex((dns_host, dns_port))
			try:
				port_service = socket.getservbyport(dns_port)
			except:
				port_service = ''
			if result == 0:
				self.SendMsg(canal, banner + '0,1[4 PORTSCAN 0]15 {}4 =>0 PORTA ABERTA:9 {} 0-4({}) '.format(str(dns_host), str(dns_port), str(port_service)))
				self.portscan_find = True
		except:
			pass
		sock.close()

	def Parse(self, banner, canal, user, cmd):
		tmp = cmd.split()
		numargs = len(tmp)
		fmt = []

		if (len(str(cmd).split()) == 0):
			return
			
		command = cmd
		command = command.split()

		# for i in range(numargs):
		# 	fmt.append(tmp[i] + ' ')

		# if user in self.admin:

		########## FUNCOES
		
		if len(command) == 1:
			if canal != self.nick:
				if command[0] == 'help' or command[0] == 'ajuda':
					self.SendMsg(canal, banner + '0,1[4 HELP 0] 15Comandos disponíveis 4->14 http://pastebin.com/ZB1LUfGB')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'ip 4........0: 4<ip/host>0 Checar informações do IP/HOST.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'dns 4.......0: 4<ip/host>0 Resolver host/domínio de determinado endereço.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'ssh 4.......0: 4<ip/host> <login> <senha>0 Testar conexão em um servidor ssh.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'ftp 4.......0: 4<ip/host> <login> <senha>0 Testar conexão em um servidor ftp.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'port 4......0: 4<ip/host> <porta>0 Checar se determinada porta está aberta.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'portscan 4..0: 4<ip/host>0 Verificar portas abertas de um endereço.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'hex 4.......0: 4<string>0 Converter string para HEXADECIMAL e ' + str(self.prefix) + 'dehex para decodificar.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'hash 4......0: 4<senha>0 Converter senha para vários tipos de HASH.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'hashkill 4..0: 4<hash>0 Busca o REVERSE da hash e mostra o seu tipo.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'google 4....0: 4<palavra/chave>0 Mostra os principais resultados do motor de busca da Google.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] ' + str(self.prefix) + 'bitcoin 4...0: Checar cotação do bitcoin do dia.')
					#self.SendMsg(canal, banner + '0,5[4HELP0] 4Python IRC Bot - Coded by ins3ct and Zirou - #nosafe / Priv8')

			if command[0] == 'rehash':
				if user in self.admin:
					time.sleep(1)
					self.SendCommand('QUIT #Sua saída aqui ')
					self.s.close()
					self.close = True
					exit(1)
				else:
					self.SendMsg(canal, banner + '4,1 Você não tem permissão.')

			if command[0] == 'bitcoin':
				try:
					btc = requests.get('https://btc-e.com/api/3/ticker/btc_usd')
					btc_data = btc.json()

					bit_max = btc_data['btc_usd']['high']
					bit_min = btc_data['btc_usd']['low']
					bit_buy = btc_data['btc_usd']['buy']
					bit_sell = btc_data['btc_usd']['sell']
					
					self.SendMsg(canal, banner + '0,1[4 BITCOIN 0] MAX/USD:14 {:.6} 0MIN/USD:14 {:.6} 0BUY/USD:14 {:.6} 0SELL/USD:14 {:.6} '.format(str(bit_max), str(bit_min), str(bit_buy), str(bit_sell)))
				except Exception, e:
					print '[BITCOIN] ERRO:', e

			if command[0] == 'cpf123123':
				arNumeros = []
				for i in range(9):
					arNumeros.append(randint(0,9))
				somaJ = (arNumeros[0]*10)+(arNumeros[1]*9)+(arNumeros[2]*8)+(arNumeros[3]*7)+(arNumeros[4]*6)+(arNumeros[5]*5)+(arNumeros[6]*4)+(arNumeros[7]*3)+(arNumeros[8]*2)
				restoJ = somaJ % 11
				if (restoJ == 0 or restoJ == 1):
					j = 0
				else:
					j = 11 - restoJ
				arNumeros.append(j)
				somaK = (arNumeros[0]*11)+(arNumeros[1]*10)+(arNumeros[2]*9)+(arNumeros[3]*8)+(arNumeros[4]*7)+(arNumeros[5]*6)+(arNumeros[6]*5)+(arNumeros[7]*4)+(arNumeros[8]*3)+(j*2)
				restoK = somaK % 11
				if (restoK == 0 or restoK == 1):
					k = 0
				else:
					k = 11 - restoK
				arNumeros.append(k)
				cpf = ''.join(str(x) for x in arNumeros)
				cpf = cpf[:3] + '.' + cpf[3:6] + '.' + cpf[6:9] + '-' + cpf[9:]

				self.SendMsg(canal, banner + '0,1[4 CPF 0] GERADOR 4=>9 {} '.format(str(cpf)))

		else:

			if command[0] == 'join':
				if user in self.admin:
					if command[1][0] == '#':
						join_channel = command[1]
					else:
						join_channel = '#' + command[1]
					self.SendCommand('JOIN %s' % join_channel)
				else:
					self.SendMsg(canal, banner + '4,1 Você não tem permissão.')

			if command[0] == 'part':
				if user in self.admin:
					if command[1][0] == '#':
						part_channel = command[1]
					else:
						part_channel = '#' + command[1]
					self.SendCommand('PART %s Let\'s Rock!' % part_channel)
				else:
					self.SendMsg(canal, banner + '4,1 Você não tem permissão.')

			if command[0] == 'cmd':
				if user in self.admin:
					self.SendCommand(' '.join(command[1:]))
				else:
					self.SendMsg(canal, banner + '4,1 Você não tem permissão.')

			if canal != self.nick:

				if command[0] == 'sendall':
					if user in self.admin:
						try:
							sendall_msg = ' '.join(command[1:])
							self.SendAllChans(user, canal, self.banner + sendall_msg)
						except:
							self.SendMsg(canal, 'Algo deu errado.')

# IP ANTIGO:
#				if command[0] == 'ip':
#					try:
#						ip_host		= command[1]
#						self.SendMsg(canal, banner + '0,1[4 IP 0] Checando 15[{}] '.format(str(ip_host)))
#						ip_ips = socket.gethostbyname_ex(ip_host)[2]
#						try:
#							ip_ipv6	= socket.getaddrinfo(ip_host, 80, socket.AF_INET6)[0][4][0]
#							ip_ips.append(ip_ipv6)
#						except Exception, e:
#							print canal, '0,1[4 IP 0]4 [IPV6] {} '.format(str(e))
#						for ip in ip_ips:
#							try:
#								try:
#									ip_ip = socket.gethostbyname(ip)
#								except Exception, e:
#									ip_ip = ip_host
#									print '[GETHOSTBYNAME]', e
#								try:									
#									ip_reverse = socket.gethostbyaddr(ip)[0]
#								except Exception, e:
#									ip_reverse = 'no/rdns'
#									# print '[IPV6 ERROR]', e
#								try:
#									r = requests.get('http://ip-api.com/json/' + str(ip_ip))
#									resp = r.json()
#									
#									ip_empresa	= resp['org']# if (len(str(resp['org'])) > 1) else '---'
#									ip_pais		= resp['country']# if (len(str(resp['country'])) > 1) else '---'
#									ip_cidade	= resp['city']# if (len(cidade) > 1) else '---'
#									ip_reg_nome	= resp['regionName']# if (len(str(resp['lon'])) > 1) else '---'
#
#									ip_empresa = ip_empresa.encode('utf-8')
#									ip_pais = ip_pais.encode('utf-8')
#									ip_cidade = ip_cidade.encode('utf-8')
#									ip_reg_nome = ip_reg_nome.encode('utf-8')
#
#									self.SendMsg(canal, banner + '0,1[4 IP 0]15 {} 4=> 0[14Organização0]:15 {} '.format(str(ip), str(ip_empresa)))
#									self.SendMsg(canal, banner + '0,1[4 IP 0]15 {} 4=> 0[14Localização0]:15 {} / {} - {} '.format(str(ip), str(ip_pais), ip_cidade, str(ip_reg_nome)))
#									self.SendMsg(canal, banner + '0,1[4 IP 0]15 {} 4=> 0[14DNS Reverso0]:15 {} '.format(str(ip), str(ip_reverse)))
#									self.SendMsg(canal, banner + '0,1[4 IP 0]4 {} - Completed! '.format(str(ip)))
#
#								except Exception, e:
#									print 'ERRO:', e
#									# self.SendMsg(canal, banner + '0,1[4 IP 0]4 FUNC1 - {}'.format(str(e)))
#
#							except Exception, e:
#								print 'ERRO:', e
#								# self.SendMsg(canal, banner + '0,1[4 IP 0]4 FUNC2 {}'.format(str(e)))
#
#					except Exception, e:
#						print 'ERRO:', e
#						self.SendMsg(canal, banner + '0,1[4 IP 0]4 Host não encontrado.')
# IP NOVO:

				if command[0] == 'ip':
					try:
						host = command[1]
						ips = []
						self.SendMsg(canal, banner + '0,1[4 IP 0] Checando 15[{}] '.format(host))
						for ip in socket.getaddrinfo(host, 0):
							if ip[4][0] not in ips:
								ips.append(ip[4][0])
						for hosts in ips:
							try:
								reverse = socket.gethostbyaddr(hosts)[0]
							except:
								reverse = 'no/rdns'
							r = requests.get('http://ip-api.com/json/' + str(hosts))
							resp = r.json()

							ip_empresa	= resp['org']
							ip_pais		= resp['country']
							ip_cidade	= resp['city']
							ip_reg_nome	= resp['regionName']

							ip_empresa = ip_empresa.encode('utf-8')
							ip_pais = ip_pais.encode('utf-8')
							ip_cidade = ip_cidade.encode('utf-8')
							ip_reg_nome = ip_reg_nome.encode('utf-8')

							self.SendMsg(canal, banner + '0,1[4 IP 0]15 {} 4=> 0[14Organização0]:15 {} '.format(hosts, str(ip_empresa)))
							self.SendMsg(canal, banner + '0,1[4 IP 0]15 {} 4=> 0[14Localização0]:15 {} / {} - {} '.format(hosts, str(ip_pais), ip_cidade, str(ip_reg_nome)))
							self.SendMsg(canal, banner + '0,1[4 IP 0]15 {} 4=> 0[14DNS Reverso0]:15 {} '.format(hosts, reverse))
							self.SendMsg(canal, banner + '0,1[4 IP 0]4 {} - Completed! '.format(hosts))
					except Exception, e:
						self.SendMsg(canal, banner + '0,1[4 IP 0]4 Endereço não encontrado. ')

# DNS ANTIGO:
#				if command[0] == 'dns':
#					dns_host = command[1]
#					# self.SendMsg(canal, banner + '0,1[4 DNS 0] Checando15 [{}] '.format(str(command[1])))
#					try:
#						dns_ips	= socket.gethostbyname_ex(dns_host)
#						try:
#							dns_reverse = socket.gethostbyaddr(dns_host)
#							dns_ipv6	= socket.getaddrinfo(dns_host, 80, socket.AF_INET6)[0][4][0]
#						except Exception, e:
#							print 'ERRO:', e
#							pass
#						for ip in dns_ips[2]:
#							try:
#								dns_local_reverse = socket.gethostbyaddr(ip)[0]
#							except Exception, e:
#								print 'ERRO:', e
#								dns_local_reverse = 'no/rdns'
#							self.SendMsg(canal, banner + '0,1[4 DNS 0]15 {} 4=>14 {} 4({}) '.format(str(dns_host), str(ip), str(dns_local_reverse)))
#						try:
#							try:
#								dns_ipv6_reverse = socket.gethostbyaddr(dns_ipv6)[0]
#							except Exception, e:
#								print 'ERRO:', e
#								dns_local_reverse = 'no/rdns'
#							self.SendMsg(canal, banner + '0,1[4 DNS 0]15 {} 4=>14 {} 4({}) '.format(str(dns_host), str(dns_ipv6), str(dns_ipv6_reverse)))
#						except Exception, e:
#							print 'ERRO:', e
#							pass
#					except Exception, e:
#						print 'ERRO:', e
# DNS NOVO:
				if command[0] == 'dns':
					try:
						host = command[1]
						dnss = []
						self.SendMsg(canal, banner + '0,1[4 DNS 0] Checando 15[{}] '.format(host))
						for dns in socket.getaddrinfo(host, 0):
							if dns[4][0] not in dnss:
								dnss.append(dns[4][0])
						for hosts in dnss:
							try:
								reverse = socket.gethostbyaddr(hosts)[0]
							except:
								reverse = 'no/rdns'
							self.SendMsg(canal, banner + '0,1[4 DNS 0]15 {} 4=>14 {} 4({}) '.format(host, hosts, reverse))
					except:
						self.SendMsg(canal, banner + '0,1[4 DNS 0]4 Endereço não encontrado. ')

# ANTIGO PORT:
#				if command[0] == 'port':
#					try:
#						port_host = command[1]
#						port_port = command[2]
#						try:
#							port_iplist = socket.gethostbyname_ex(port_host)[2]
#						except:
#							port_iplist = []
#							port_iplist.append(socket.gethostbyaddr(port_host)[2])
#						try:
#							port_ipv6 = socket.getaddrinfo(port_host, port_port, socket.AF_INET6)[0][4][0]
#							port_iplist.append(port_ipv6)
#						except:
#							pass
#						self.SendMsg(canal, banner + '0,1[4 PORT 0] Checando15 [{}] '.format(str(port_host), str(port_port)))
#
#						try:
#							for host_ip in port_iplist:
#								run_connect = threading.Thread(target = self.PortConnect, args=(banner, canal, host_ip, int(port_port)))
#								run_connect.start()
#						except:
#							pass
#
#					except Exception, e:
#						self.SendMsg(canal, banner + '0,1[4 PORT 0]4 {} '.format(str(e)))
# NOVO PORT:				

				if command[0] == 'port':
					try:
						port_host = command[1]
						port_port = command[2]
						port_dns = []

						self.SendMsg(canal, banner + '0,1[4 PORT 0] Checando15 [{}] '.format(str(port_host), str(port_port)))

						for dns in socket.getaddrinfo(port_host, 0):
							if dns[4][0] not in port_dns:
								port_dns.append(dns[4][0])
						try:
							for port_hosts in port_dns:
								run_connect = threading.Thread(target = self.PortConnect, args=(banner, canal, port_hosts, int(port_port)))
								run_connect.start()
						except Exception, e:
							print e
					except Exception, e:
						print e

				if command[0] == 'range':
					try:
						port_host = command[1]
						port_port = command[2]

						port_list_scan = []						
						try:
							port_host_split_in = port_host.split('.')[3].split('-')[0]
							port_host_split_fin = port_host.split('.')[3].split('-')[1]

							if (int(port_host_split_in) > (int(port_host_split_fin))):
								self.SendMsg(canal, banner + '0,1[4 RANGE 0]4 Erro: O host de início não pode ser maior. ')
								return
							
							if (int(port_host_split_fin) - int(port_host_split_in)) > 5 and user not in self.admin:
								self.SendMsg(canal, banner + '0,1[4 RANGE 0]4 Use no máximo 5 ips de range. ')
								return

							for x in range(int(port_host_split_in), (int(port_host_split_fin) + 1)):
								port_list_scan.append(('.'.join(port_host.split('.')[:3])) + '.' + str(x))
								# print (('.'.join(port_host.split('.')[:3])) + '.' + str(x))

						except Exception, e:
							print '>>>>', e

						try:
							for host_ip in port_list_scan:
								# self.SendMsg(canal, banner + '0,5[4 RANGEPORT 0] Checando4 {}:{} '.format(str(host_ip), str(port_port)))
								time.sleep(2)
								run_connect = threading.Thread(target = self.PortConnect, args=(banner, canal, host_ip, int(port_port)))
								run_connect.start()
						except:
							pass

					except Exception, e:
						self.SendMsg(canal, banner + '0,1[4 RANGEPORT 0]4 {} '.format(str(e)))

				if command[0] == 'portscan':
					dns_host = command[1]
					self.portscan_find = False
					self.SendMsg(canal, banner + '0,1[4 PORTSCAN 0] Checando15 [{}] '.format(str(dns_host)))

					port_list = [1,5,7,18,20,21,22,23,25,29,37,42,
								43,49,53,69,70,79,80,103,108,109,
								110,115,118,119,137,139,143,150,
								156,161,179,190,194,9000,197,389,396,
								443,444,445,458,546,8080,547,563,9,
								1080,3389,6667,6697,8002,34567,34599]
					try:
						for port in port_list:
							run_scan = threading.Thread(target = self.PortScan, args=(banner, canal, dns_host, int(port)))
							run_scan.start()
					except Exception, e:
						print 'ERRO:', e
					time.sleep(8)
					if not self.portscan_find:
						self.SendMsg(canal, banner + '0,1[4 PORTSCAN 0] 4Nenhuma porta encontrada. ')

				if command[0] == 'sshfull':
					ssh_host = command[1]
					try:
						ssh_user = command[2]
						ssh_pass = command[3]

						try:
							run_ssh = threading.Thread(target = self.SSHConnect, args=(banner, canal, ssh_host, ssh_user, ssh_pass))
							run_ssh.start()
						except:
							self.SendMsg(canal, banner + '4,1 Conexão não permitida. ')
					except:
						self.SendMsg(canal, banner + '0,1 Por favor, use:15 ' + self.prefix + 'ssh <host> <usuario> <senha> ')

				if command[0] == 'exec':
					exec_host = command[1]
					try:
						exec_user = command[2]
						exec_pass = command[3]
						exec_cmd  = ' '.join(command[4:])

						try:
							run_ssh = threading.Thread(target = self.SSHExec, args=(banner, canal, exec_host, exec_user, exec_pass, exec_cmd))
							run_ssh.start()
						except:
							self.SendMsg(canal, banner + '4,1 Conexão não permitida. ')
					except:
						self.SendMsg(canal, banner + '0,1 Por favor, use:15 ' + self.prefix + 'exec <host> <usuario> <senha> <comando> ')

				if command[0] == 'ssh':
					command = command[1]
					try:
						if command.find(';') != -1:
							ssh_host, ssh_user, ssh_pass = command.split(';')
						elif command.find(':') != -1:
							ssh_host, ssh_user, ssh_pass = command.split(':')
						else:
							self.SendMsg(canal, banner + '0,1 Por favor, use:15 ' + self.prefix + 'ssh <host>:<usuario>:<senha> ')	
						try:
							run_ssh = threading.Thread(target = self.SSHConnect1, args=(banner, canal, ssh_host, ssh_user, ssh_pass))
							run_ssh.start()
						except Exception, e:
							pass
							# self.SendMsg(canal, '4,1 {}'.format(str(e)))
					except Exception, e:
						self.SendMsg(canal, banner + '0,1 Por favor, use:15 ' + self.prefix + 'ssh <host>:<usuario>:<senha> ')

				if command[0] == 'ftp':
					ftp_host = command[1]
					try:
						ftp_user = command[2]
						ftp_pass = command[3]

						try:
							run_ftp = threading.Thread(target = self.FTPConnect, args=(banner, canal, ftp_host, ftp_user, ftp_pass))
							run_ftp.start()
						except:
							self.SendMsg(canal, 'Conexão não permitida')
					except:
						self.SendMsg(canal, banner + '0,1 Por favor, use: 15' + self.prefix + 'ftp <host> <usuario> <senha>')

				if command[0] == 'hash':
					try:
						hash_cmd = command[1]
						hash_md5 = hashlib.md5(hash_cmd).hexdigest()
						hash_sha1 = hashlib.sha1(hash_cmd).hexdigest()
						hash_sha256 = hashlib.sha256(hash_cmd).hexdigest()

						self.SendMsg(canal, banner + '0,1[4 HASH 0]14 MD5 4=>15 {}'.format(str(hash_md5)))
						self.SendMsg(canal, banner + '0,1[4 HASH 0]14 SHA1 4=>15 {}'.format(str(hash_sha1)))
						self.SendMsg(canal, banner + '0,1[4 HASH 0]14 SHA256 4=>15 {}'.format(str(hash_sha256)))

					except:
						self.SendMsg(canal, banner + '0,1 Por favor, use:15 ' + self.prefix + 'hash <senha>')

				if command[0] == 'hashkill':
					try:
						hashkill_hash = command[1]
						self.SendMsg(canal, banner + '0,1[4 HASHKILL 0]14 Checando:15 {} '.format(str(hashkill_hash)))
						r = requests.get('http://hashtoolkit.com/reverse-hash?hash=' + str(hashkill_hash))
						soup = BeautifulSoup.BeautifulSoup(r.text)
						hash_type = soup.tbody.td.text
						hashkill_list = []

						for result in soup.findAll('td', {'class':'res-text'}):
							hashkill_resolved = result.span.text
							hashkill_list.append(str(hashkill_resolved))
						if len(hashkill_list) == 1:
							for hashes in hashkill_list:
								self.SendMsg(canal, banner + '0,1[4 HASHKILL 0]14 Encontrado 4=>9 {} 4=>14 ({}) '.format(str(hashes), str(hash_type)))
						else:
							self.SendMsg(canal, banner + '0,1[4 HASHKILL 0]4 Hash não encontrada. ')
					except:
						self.SendMsg(canal, banner + '0,1[4 HASHKILL 0]4 Hash não encontrada. ')

				if command[0] == 'hex':
					try:
						hex_string = ' '.join(command[1:])
						hex_hex = base64.b16encode(hex_string)
						hex_spaced = []

						try:
							space_list = []
					 		for string in range(0, len(hex_hex), 2):
					 			hex_spaced.append(' '+ hex_hex[string:(string+2)])
					 		hex_completed = ' '.join((hex_spaced)).strip()
							self.SendMsg(canal, banner + '0,1[4 HEX 0]14 STRING:15 {} 14HEX:15 [{}] '.format(str(hex_string), str(hex_completed.lstrip())))					 	
					 	except:
					 		pass
					except:
						self.SendMsg(canal, banner + '0,1 Por favor, use:14 ' + self.prefix + 'hex <string>')

				if command[0] == 'dehex':
					try:
						hex_string = command[1:]
						hex_join = ''.join(hex_string)
						try:
							hex_decoded = base64.b16decode(hex_join)
							self.SendMsg(canal, banner + '0,1[4 HEX 0]14 HEX 4=>14 STRING:8 {}'.format(str(hex_decoded.lstrip())))
						except:
							self.SendMsg(canal, '0,1 Valor hexadecimal incorreto. Use:14 ' + self.prefix + 'dehex <hexadecimal>')
					except:
						self.SendMsg(canal, banner + '0,1Por favor, use:14 ' + self.prefix + 'dehex <string>')

				if command[0] == 'google':
					try:
						google_search = ' '.join(command[1:])
						url = 'http://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=' + str(google_search)

						r = requests.get(url)
						objects = r.json()

						for result in objects['responseData']['results']:
							titl = result['titleNoFormatting']
							ress = result['unescapedUrl']
							self.SendMsg(canal, banner + '0,1[4 GOOGLE 0] {}'.format(titl.encode('utf-8')))
							self.SendMsg(canal, banner + '0,1[4 GOOGLE 0]14 URL:14 {}'.format(ress.encode('utf-8')))

					except Exception, e:
						print 'ERROR:', e

				if command[0] == 'encurtar':
					try:
						url = urllib.urlopen('http://migre.me/api.txt?url=' + urllib.quote(str(command[1]))).read()
						self.SendMsg(canal, banner + '0,1[4 ENCURTADOR 0] URL 4=>15 {} '.format(url))
					except Exception, e:
						print 'ERROR:', e

				if command[0] == 'queporta':
					try:
						queporta_service = socket.getservbyport(int(command[1]))
						self.SendMsg(canal, banner + '0,1[4 QUEPORTA 0] PORTA:15 {}4 =>9 {} '.format(int(command[1]), str(queporta_service).upper()))
					except Exception, e: 
						self.SendMsg(canal, banner + '0,1[4 QUEPORTA 0]4 {} '.format(str(e).capitalize()))

				if command[0] == 'ping':
					try:
						ping_host = command[1]
						ping_response = os.system('ping -c 1 ' + ping_host)
						if ping_response == 0:
							self.SendMsg(canal, banner + '0,1[4 PING 0] HOST:14 {} 4=>9 ON '.format(str(ping_host)))
						else:
							self.SendMsg(canal, banner + '0,1[4 PING 0] HOST:14 {} 8=>4 OFF '.format(str(ping_host)))
					except Exception, e:
						self.SendMsg(canal, banner + '0,1[4 PING 0]4 {} '.format(str(e)))

	def run(self):

		self.SendCommand('NICK ' + self.nick)
		self.SendCommand('USER ' + self.nick + ' ' + self.name + 
			' ' + self.email + ' :' +
			base64.b16decode('507974686F6E20426F7420636F64656420696E2050726976382F234E4F53414645'))

		while self.close == False:

			self.data = self.s.recv(4096)
			
			if self.verbose:
				print self.data

			self.SendPingResponse()
			
			time.sleep(0.5)
			
			if str(self.data).find(str(base64.b16decode('#####'))) != -1:
				print '\nServer [{}] - CONNECTED! Thank\'s to use NOSAFE BOT!\n'.format(self.server)
				self.SendMsg(str(base64.b16decode('#####')), str(base64.b16decode('#####')))
			if str(self.data).find(str(base64.b16decode('#####'))) != -1:
				self.s.send('{}'.format(base64.b16decode('#####')) + '\r\n')
			if str(self.data).find(str(base64.b16decode('#####'))) != -1:
				self.s.send('JOIN {}\r\n'.format(self.channel))
				for channel in ajoin:self.s.send('JOIN {}\r\n'.format(channel))

			if str(self.data).find('PRIVMSG') != -1: # Confere se o dado recebido foi uma mensagem private ou para algum canal
				
				msg_time  = time.strftime('%H:%M:%S')		# Define a hora da mensagem
				user_nick = self.data.split('!')[0][1:] 	# Filtra o nick
				try:
					user_host = self.data.split()[0].split('@')[1] # Tenta filtrar o host (Variável ainda não usada)
				except:
					pass
				
				pre_user_msg	= self.data[1:].split('PRIVMSG')[1].split()[1:]	# Trabalha a mensagem bruta
				user_msg 		= ' '.join(pre_user_msg).lstrip(':') 					# Filtra apenas a mensagem
				user_channel 	= str(self.data.split('PRIVMSG')[1].split()[0])	# Filtra o canal

				print '[%s] %s %s: %s' % (str(msg_time), str(user_channel), str(user_nick), str(user_msg)) # Imprime a mensagem na tela do bot

				text_log = '[{}] {}: {}'.format(str(msg_time), str(user_nick), str(user_msg)) # Filtra o a mensagem para a função Logging()

				
				self.Logging(str(user_channel), str(user_nick), str(text_log)) # Grava os logs

				# Banner oficial:
				banner = '14,1[#' + user_channel[1:] + '#Seu banner aqui] '

				try:
					if (str(user_msg)[0] == str(self.prefix)):
						self.Parse(banner, user_channel, user_nick, user_msg.lstrip(str(self.prefix))) # Chama a função Parse que gera todas as outras funções
				except:
					continue

#			self.SendCommand('NICK ' + self.nick)

			
if __name__ == '__main__':

	servidor = ''
	porta = 
	nick = ''
	nome = ''
	email = ''
	canal_principal = '' # Canal de comando do bot
	ajoin = []# Canais secundários, .sendall enviará mensagem para esses canais.
	admin = [] # Nicks para acessos à funções especiais do bot
	prefix = '.' # Prefixo para uso dos comandos
	verbose = True

	simple_banner = '14,1[#Seu banner aqui]0 '

bot = NoSafe(servidor, porta, nick, nome, email, canal_principal, ajoin, admin, prefix, verbose, simple_banner)
bot.run()
