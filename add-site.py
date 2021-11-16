import sys

buf_http = "alert tcp any any -> any 80 (msg:\"%s access\"; content: \"GET /\"; content:\"Host: \"; content:\"%s\"; sid:%d; rev:1;)\r\n"
buf_https = "alert tcp any any -> any 443 (msg:\"%s access\"; content:\"%s\"; sid:%d; rev:1;)\r\n"

f_arr = [buf_http, buf_https]

def usage():
    print("add-site.py {rules file} {--http or --https} {site name}")
    exit()

argc = len(sys.argv)
argv = sys.argv

if(argc != 4):
    usage()

if(argv[2] != '--http' and sys.argv[2] != '--https'):
    usage()

format_idx = 0

if(argv[2] == '--https'): 
    format_idx = 1

rules_name = argv[1]

total_buf = ''

with open(rules_name, 'r') as f:
    bufs = f.readlines()

sid_buf = bufs[-1]
idx1 = sid_buf.find('sid:') + 4
idx2 = sid_buf.find('; rev')
sid = int(sid_buf[idx1:idx2]) + 1

bufs.append( ( f_arr[format_idx]%(argv[3], argv[3], sid) ) )

for o in bufs:
    total_buf += o

with open(rules_name, 'w') as f:
    f.write(total_buf)