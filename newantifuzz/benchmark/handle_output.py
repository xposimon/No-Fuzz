import os

queue_list = []
os.system("rm -rf ./com_output")
os.system("mkdir ./com_output")
for r, d, f in os.walk("./"):
#    print(r)
    if "output" in r and r.endswith("queue") and 'results' not in r:
        taskname = r.split("/")[2]
        if taskname not in queue_list:
            queue_list.append(taskname)        
            print(taskname)
            os.system("cp -r "+r+" ./com_output/"+taskname)
    if r.endswith("output2") and "results" not in r:
        taskname = r.split("/")[2]
        if taskname not in queue_list:
            queue_list.append(taskname)
            print(taskname)
            os.system("cp -r " +r+" ./com_output/" + taskname)


