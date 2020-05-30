import socket
import hashlib
import zlib
import argparse

# take inputs at command line using argparse
parser = argparse.ArgumentParser()
parser.add_argument('--keys')
parser.add_argument('--binaries')
parser.add_argument('-d')
parser.add_argument('-p')
args = parser.parse_args() #call the values with args

#for key
pubkey_filename = args.keys
pubkey_filename = pubkey_filename.replace('\\','')  #replace the escape characters with blank
pubkey_filename = eval(pubkey_filename) #evaluate the string which is a dictionary
#for binary
bin_filename = args.binaries  #same steps as key
bin_filename = bin_filename.replace('\\','')
bin_filename = eval(bin_filename)
delay = int(args.d)
input_port = int(args.p)  #port number

#function to decrypt the signature and validate the signature
def decrypt_sign(file_data,udp_packet_id,udp_seq_no,sig,data):
	e = int.from_bytes(file_data[:3],byteorder='big') #first 3 bytes
	n = int.from_bytes(file_data[3:],byteorder='big') #remaining 64 bytes of the key file
	sig_int = int.from_bytes( sig , byteorder='big')
	sig_decrypt = hex(pow(sig_int , e , n))
	sig_hash = "0x"+sig_decrypt[-64:].lstrip("0")
	data_hash = hex(int.from_bytes(hashlib.sha256(data).digest(), byteorder='big'))
	if sig_hash != data_hash: #checking for faulty hash
		output = udp_packet_id + "\n" + str(int(udp_seq_no,16)) + "\n" + sig_hash.lstrip("0x") + "\n" + data_hash.lstrip("0x") + "\n" +"\n"
	else:
		output = ''
	return output		

#function to write in the verification.log
def write_to_file(output1,output2):
	with open("verification_failures.log",'a') as fsig, open("checksum_failures.log",'a') as fchk:
		fsig.write(output1)
		fchk.write(output2)

#function to verify the checksum
def verify_checksum(file_data,packet_id,key,seq_no,data,prev,end_val):
	output = ''
	seq_no = int(seq_no,16)
	key = key.lstrip('0x')
	if len(key) < 4: #edge case verification for key
		key = "0"*(4 - len(key)) + key
	key = int(key+key,16)
	data = data.lstrip('0x')
	if len(data) % 8 !=0: #edge case verification for data
		data = "0"*(8 - (len(data) % 8)) + data
	if end_val != seq_no: #edge case verification for missed udp packets
		for i in range(end_val,seq_no):
			prev = zlib.crc32(file_data,prev)
	recv_len = 0
	for i in range(0,len(data),8):
		prev = zlib.crc32(file_data,prev)
		crc32 = int(data[i:i+8],16) ^ key 
		if prev != crc32:
			output += packet_id + "\n" + str(seq_no) + "\n" + str(seq_no+recv_len) + "\n" + ('%x' %crc32)+ "\n" + ('%x' %prev) + "\n" + "\n"
		recv_len += 1
	end_val = seq_no + recv_len
	return [output,prev,end_val]

#get the user input
UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = input_port
try:
	Sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	print ("Socket created")
except:
	print ("Failed to create a socket.")

try:
	Sock.bind((UDP_IP_ADDRESS, UDP_PORT_NO))
except:
	print ("Bind Failed,  Please make sure the UDP port is not already in use.")
	print ("Use 'fuser -k 1337/udp' to free the socket")

i = 0
sig_result = ''
chcksm_presult = ''
binfile_data = {}
pubfile_data = {}
prev_dict = {}
end_val_dict = {}

for pid in bin_filename:
	value = bin_filename[pid]
	#opening file here
	with open(bin_filename[pid],'rb') as binary:
		binfile_data[pid] = binary.read()
		binfile_data[pid+"_prev"] = 0
		binfile_data[pid+"_end_val"] = 0

for pid in pubkey_filename:
	with open(pubkey_filename[pid],'rb') as binary:
		pubfile_data[pid] = binary.read()
while True:
	data, addr = Sock.recvfrom(2048)
	#fragmentation of the packet
	udp_packet_id = hex(int.from_bytes( data[0:4] , byteorder='big'))
	udp_seq_no = hex(int.from_bytes( data[4:8] , byteorder='big'))
	udp_XOR_key = hex(int.from_bytes( data[8:10] , byteorder='big'))
	udp_checksum = hex(int.from_bytes( data[10:12] , byteorder='big'))
	udp_data = hex(int.from_bytes( data[12:-64] , byteorder='big'))
	udp_sig = data[-64:]
	data2 = data[0:-64]
	"""#print ("UDP raw data: ", data)
	print ("---------Fragmented UDP data------------")
	print ("Packet id: ", udp_packet_id)
	print ("Sequence number: ", udp_seq_no)
	print ("XOR key: ", udp_XOR_key)
	print ("Checksum: ", udp_checksum)
	print ("Data: ", udp_data)
	#print ("RSA Signature: ", udp_sig)"""
	publickey_data = pubfile_data[udp_packet_id]
	binary_data = binfile_data[udp_packet_id]
	prev = binfile_data[udp_packet_id+"_prev"]
	end_val = binfile_data[udp_packet_id+"_end_val"]
	sig_result += decrypt_sign(publickey_data,udp_packet_id,udp_seq_no,udp_sig,data2)
	chcksm_result = verify_checksum(binary_data,udp_packet_id,udp_XOR_key,udp_seq_no,udp_data,prev,end_val)
	chcksm_presult += chcksm_result[0]
	binfile_data[udp_packet_id+"_prev"] = chcksm_result[1]
	binfile_data[udp_packet_id+"_end_val"] = chcksm_result[2]
	i +=1
	if i%240 == 0: 
		write_to_file(sig_result,chcksm_presult)
		sig_result = ''
		chcksm_presult = ''
#end