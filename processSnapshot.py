from ParseMFT import ParseMFT

new_data_file='MFT_20-04-30-18_13_34.bin'

m=ParseMFT()
d=m.process_mft_snapshot(new_data_file)
print(d)