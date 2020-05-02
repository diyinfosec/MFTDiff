from datetime import datetime
from hashlib import sha1
'''
import win32api

drives = win32api.GetLogicalDriveStrings()
drives = drives.split('\000')[:-1]
print(drives)

'''


class ParseMFT:
	SECTOR_SIZE = 512
	MFT_RECORD_SIZE = 1024

	def read_boot_record(self,fd):
				#- Reading the BIOS parameter block and locating the $MFT
				#- TODO - Instead of hardcoding SECTOR_SIZE see if you can read say 1000 bytes and determine the sector size form there. 
				#- TODO - Derive size of the MFT record from the BPB
			first_sector = fd.read(ParseMFT.SECTOR_SIZE)

			'''
			11 - Bytes per sector - 2 bytes
			13 - Sectors per cluster - 1 byte
			48 - MFT Cluster Number - 8 bytes
			Ref: https://www.delftstack.com/howto/python/how-to-convert-bytes-to-integers/
			'''
			bytes_per_sector = int.from_bytes(first_sector[11:13:],byteorder='little')
			sectors_per_cluster = int.from_bytes(first_sector[13:14:],byteorder='little')
			cluster_size = bytes_per_sector * sectors_per_cluster
			mft_cluster_num = int.from_bytes(first_sector[48:56:],byteorder='little')		
			
			mft_offset = (mft_cluster_num * cluster_size) 

			print('Bytes per sector is %s'%(bytes_per_sector))
			print('Sectors per cluster is %s'%(sectors_per_cluster))
			print('MFT cluster number is %s'%(mft_cluster_num))
			print('Offset to MFT is %s'%(mft_offset))

			d={}

			d['cluster_size'] = cluster_size
			d['mft_offset'] = mft_offset

			return d

	def read_mft_record(self,fd,offset):
			#- Reading the FILE record of $MFT
			#- Seek should ALWAYS be a multiple of sector size for direct disk access. 
			#- Refer: https://support.microsoft.com/en-ie/help/100027/info-direct-drive-access-under-win32
			fd.seek(offset)
			
			return fd.read(ParseMFT.MFT_RECORD_SIZE)


	def parse_mft_record_header(self,mft_record):

		#- Dictionary to hold the parsed fields in the MFT record. 
		d={}

		#- If the set of bytes begins with FILE then it's a valid MFT record. 
		#-  otherwise set the valid flat to N and return. 
		d['signature']=mft_record[0:4]
		if d['signature'] == b'FILE':
			#print("File record!")
			d['is_valid_record']='Y'
			d['update_seq_offset'] = int.from_bytes(mft_record[4:6],byteorder='little')
			d['update_seq_size'] = int.from_bytes(mft_record[6:8],byteorder='little')
			d['logfile_seq'] = int.from_bytes(mft_record[8:16],byteorder='little')
			d['seq_num'] = int.from_bytes(mft_record[16:18],byteorder='little')
			d['hardlink_count'] = int.from_bytes(mft_record[18:20],byteorder='little')
			d['first_attr_offset'] = int.from_bytes(mft_record[20:22],byteorder='little')
			d['in_use_flg'] = int.from_bytes(mft_record[22:23],byteorder='little')
			d['is_dir_flg'] = int.from_bytes(mft_record[23:24],byteorder='little')
			d['real_size'] = int.from_bytes(mft_record[24:28],byteorder='little')
			d['allocated_size'] = int.from_bytes(mft_record[28:32],byteorder='little')
			#- TODO - Handling base record. 
			d['base_record'] = int.from_bytes(mft_record[32:40],byteorder='little')
			d['next_attr_num'] = int.from_bytes(mft_record[40:42],byteorder='little')
			d['reserved'] = int.from_bytes(mft_record[42:44],byteorder='little')
			d['mft_id'] = int.from_bytes(mft_record[44:48],byteorder='little')
			d['update_seq_num'] = mft_record[48:50]

			mft_header_size = 50+(d['update_seq_size']*2)
			d['update_seq_array'] = mft_record[50:mft_header_size]


			#- Apply fix up if necessary:
			if(d['real_size'] >= ParseMFT.SECTOR_SIZE):
				mod_mft_record=self.apply_fixup(mft_record,d['update_seq_array'])
				d['mft_body']=mod_mft_record[mft_header_size:d['real_size']]
				#print(d['mft_body'])

			else:
				d['mft_body'] = mft_record[mft_header_size:d['real_size']]

			d['mft_body_sha1']=sha1(d['mft_body']).hexdigest()
			#print(d)	
		else:
			d['is_valid_record']='N'
			d['mft_body_sha1'] = 'dummy'
			#print('Not a FILE record %s',mft_record[0:4])
		return d

	def apply_fixup(self,mft_record,update_seq_array):
			#- TODO: NOt sure if I should get this from BPB
			tmp_rec_size = ParseMFT.MFT_RECORD_SIZE
			sector_size = ParseMFT.SECTOR_SIZE
			tmp_mft_data = b''
			counter=0

			#- Loop till you get through all the clusters
			while tmp_rec_size >=sector_size:
				#- start_size will begin at 0 and increment by sector offset. 
				start_size=int(sector_size*(counter/2))
				
				#- Part1 will be all but last 2 bytes of the sector. 
				part1=mft_record[start_size:(start_size+sector_size-2)]
				#- Part2 will be the corresponding bytes in the Update Sequence Array. 
				part2=update_seq_array[counter:counter+2]
				#- Once done processing the sector, reduce the tmp_rec_size
				tmp_rec_size = tmp_rec_size - sector_size
				#- Append the fixup applied sector to tmp_mft_data. 
				tmp_mft_data = tmp_mft_data + part1 + part2
				#- Increment the counter
				counter=counter+2
			
			#print('Fixup done')
			
			return tmp_mft_data


	def parse_data_runs(self,data_run_bytes, cluster_size):
		#- TODO - This can be generic like icat 
		bytes_to_skip=0
		counter=1
		data_run_list=[]
		dr_temp=[]
		prev_cluster_offset=0
		for x in data_run_bytes:
			if bytes_to_skip==0:
				#- Added to handle last data run (which is always 00)
				#- Ref: https://flatcap.org/linux-ntfs/ntfs/concepts/data_runs.html
				if int(x)==0:
					break

				val1=int(hex(x)[3])
				val2=int(hex(x)[2])
				#print(val1)	
				#- Take val1 bytes, this will be the num_clusters
				num_clusters = int.from_bytes(data_run_bytes[counter:counter+val1], byteorder='little')
				#print(num_clusters)
				
				#- Take val2 bytes, this will be the cluster_offset
				#- Interpreting Cluster Offset as a 'Signed' integer as per: https://www.sciencedirect.com/topics/computer-science/starting-cluster
				cluster_offset = int.from_bytes(data_run_bytes[counter+val1:counter+val1+val2], byteorder='little', signed=True) + prev_cluster_offset
				#print(cluster_offset)

				prev_cluster_offset = cluster_offset

				data_run_list.append([cluster_offset*cluster_size, num_clusters*cluster_size])
				#- dr_temp is used for troubleshooting. 
				dr_temp.append([num_clusters, cluster_offset])

				bytes_to_skip=val1 + val2
			else:
				bytes_to_skip=bytes_to_skip-1
			counter=counter+1
			#print(hex(x))

		#print(dr_temp)

		#print(data_run_list)
		return data_run_list	
		#print(len(data_run_list))


	#- TODO - Change. This is a bad non-generic function, intended to process only $MFT
	def process_record_zero(self,mft_record_zero):

			#- TODO: Generic processing function for MFT record.
			#- TODO: Apply fixup if the $DATA attribute traverses sector boundary. 
			'''
			24 - Real Size of MFT record for $MFT - 4 bytes
			260 - Size of MFT data attribute - 4 bytes
			0x48 - MFT Cluster Number - 8 bytes
			'''
			mft_record_data_attr_size = int.from_bytes(mft_record_zero[260:264:],byteorder='little')
			#print('Size of $MFT data attribute  is %s'%(mft_record_data_attr_size))


			mft_data_attribute = mft_record_zero[256:256+mft_record_data_attr_size:]
			#print('$MFT data attribute contents %s'%(mft_data_attribute))

			mft_data_run_offset = int.from_bytes(mft_data_attribute[32:40], byteorder='little')
			#print('MFT data run begins at offset %s'%(mft_data_run_offset))

			mft_data_run=bytearray(mft_data_attribute[mft_data_run_offset:])
			#print('MFT data run is %s'%(mft_data_run))

			return mft_data_run	

	#- Todo, just pass the drive letter and add the slashes later.
	def take_mft_snapshot(self,source_drive,target_path):
		#- Open the file
		with open(source_drive,'rb') as f:

			#- Get all the metadata you need to dump the $MFT file.
			boot_data=self.read_boot_record(f)
			cluster_size=boot_data['cluster_size']
			mft_record_zero = self.read_mft_record(f, boot_data['mft_offset']) 
			mft_data_run=self.process_record_zero(mft_record_zero)
			mft_data_run_list=self.parse_data_runs(mft_data_run, cluster_size) 
			
			#- Auto-generating filename along with timestamp for the snapshot. 
			now = datetime.now()
			timestamp=now.strftime('%y-%m-%d-%H_%M_%S')
			snapshot_filename=target_path+ "MFT_"+str(timestamp) + ".bin"
			print(snapshot_filename)

			#- Open snapshot file in binary mode for writing
			snapshot_file = open(snapshot_filename, "wb")

			
			#- Walking through the Data Runs and writing bytes to the snapshot file
			for x in mft_data_run_list:
				#- Get the offset and the number of bytes required from that offset. 
				start_offset=x[0]
				total_bytes=x[1]
				
				#- Seek to the offset in the $MFT file. 
				f.seek(start_offset)

				#- Read the total number of bytes required. 
				mft_bytes=f.read(total_bytes)

				#- Write the bytes read from $MFT into the snapshot file
				snapshot_file.write(mft_bytes)

			snapshot_file.close()
			
			#- Closing the disk file
			f.close()

	def process_mft_snapshot(self,file_name):
		l=[]
		with open(file_name,'rb') as f:
			counter=0
			while True:
				mft_bytes=self.read_mft_record(f,counter*ParseMFT.MFT_RECORD_SIZE)
				#print(mft_bytes)

				if len(mft_bytes) < ParseMFT.MFT_RECORD_SIZE:
					break

				#- Parsing each MFT record into a dictionary. 
				d=self.parse_mft_record_header(mft_bytes)

				#- Appending the dictionary to a list
				l.append(d)
				
				counter = counter +1

		#- Close the snapshot file
		f.close()
		#- Return the list containing processed MFT records
		return l
