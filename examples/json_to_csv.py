import pandas as pd
import sys

pdObj = pd.read_json(sys.argv[1], lines=True)
csvData = pdObj.to_csv(index=False)
f = open("out.csv", "a")
f.write(csvData)
f.close()
