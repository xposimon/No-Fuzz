import time, subprocess

start = time.time()

CNT = 1
for i in range(CNT):
    subprocess.call(['../readelf_all', '-h', './seeds/test'])
end = time.time()
noeliminator = (end-start)/CNT


start = time.time()
for i in range(CNT):
    subprocess.call(['./readelf_all_copy', '-h', './seeds/test'])
end = time.time()

print('no eliminator', noeliminator)
print('eliminator',(end-start)/CNT)
