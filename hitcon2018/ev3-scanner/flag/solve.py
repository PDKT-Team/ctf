

flag = []

for i in range(1,13):
	temp = ''
	with open('line%d.txt' % i, 'rb') as fin:
		data = fin.readlines()
		for line in data:
			line = line.strip()
			num = int(line[-4:], 16)
			if abs(num - 0xc040) < 10:
				temp += ' '
			elif abs(num - 0x803f) < 10:
				temp += '@'
			else:
				temp += '@'
	if (i%2 == 0):
		temp = temp[::-1]
	flag.append(temp)
for line in flag:
	print line