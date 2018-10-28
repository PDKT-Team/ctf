#!/usr/bin/env python3
import sys, io, cgi, os
from PIL import Image
import zbarlight
print("Content-Type: text/html")
print("")
codes = set()
sizes = [500, 250, 100, 50]
print('<html><body>')
print('<form action="' + os.path.basename(__file__) + '" method="post" enctype="multipart/form-data">')
print('<input type="file" name="uploadFile"/>')
print('<input type="submit" value="submit"/>')
print('</form>')
print('<pre>')
try:
	form = cgi.FieldStorage()
	data = form["uploadFile"].file.read(1024 * 256)
	image= Image.open(io.BytesIO(data))
	for sz in sizes:
		image = image.resize((sz, sz))
		result= zbarlight.scan_codes('qrcode', image)
		if result == None:
			break
		if 1 < len(result):
			break
		codes.add(result[0])
	for c in sorted(list(codes)):
		print(c.decode())
	if 1 < len(codes):
		print("SECCON{" + open("flag").read().rstrip() + "}")
except:
	pass
print('</pre>')
print('</body></html>')

