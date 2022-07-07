
import pandas as pd
import sys

import subprocess as sp
pdObj = pd.read_json(sys.argv[1], lines=True)
print(pdObj.shape[0])
for i in range (0,(pdObj.shape[0])):
    pdObj.__getitem__('ts').__setitem__(i,sp.getoutput('date -d @'+str(pdObj.__getitem__('ts').__getitem__(i))))

csvData = pdObj.to_csv(index=False)
f = open("out.csv", "a")
f.write(csvData)
f.close()
