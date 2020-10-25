#! python

import random

SBOX_SIZE = 1024
NEWLINE = '\n'
TAB = '	'
FILEPATH = './device'
FILENAME_ORWG_GO = 'orwg.go'
FILE = FILEPATH + '/' + FILENAME_ORWG_GO

def output_orwg_go():
	content  = ''
	content += '/* '													+ NEWLINE
	content += ' * lixingke3650@gmail.com'								+ NEWLINE
	content += ' */'													+ NEWLINE
	content += ''														+ NEWLINE
	content += 'package device'											+ NEWLINE
	content += ''														+ NEWLINE
	content += 'const WG_DEVICE_SBOX_SIZE uint16 = ' + str(SBOX_SIZE)	+ NEWLINE
	content += 'var sbox_counter uint16 = 0'							+ NEWLINE
	content += ''														+ NEWLINE
	content += generate_sbox()											+ NEWLINE
	content += ''														+ NEWLINE
	content += 'func GetRandomForHeader() (random uint32) {'			+ NEWLINE
	content += '	defer func() {'										+ NEWLINE
	content += '		sbox_counter += 1'								+ NEWLINE
	content += '		if (sbox_counter >= WG_DEVICE_SBOX_SIZE) {'		+ NEWLINE
	content += '			sbox_counter = 0'							+ NEWLINE
	content += '		}'												+ NEWLINE
	content += '	}()'												+ NEWLINE
	content += ''														+ NEWLINE
	content += '	return HeaderRandomSBox[sbox_counter]'				+ NEWLINE
	content += '}'														+ NEWLINE

	fd = open(FILE, 'w')
	fd.write(content)
	fd.close()

def generate_sbox():
	ELE_NUMBERS_INLINE = 8
	Pool = ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F']

	Sbox = ''
	Sbox += 'var HeaderRandomSBox = [WG_DEVICE_SBOX_SIZE]uint32 {' + NEWLINE
	for _ in range(int(SBOX_SIZE/ELE_NUMBERS_INLINE)):
		Sbox += TAB
		for _ in range(ELE_NUMBERS_INLINE):
			temp = random.choice(Pool) + random.choice(Pool) + random.choice(Pool) + random.choice(Pool)
			Sbox += '0x' + temp + ', '
		Sbox += NEWLINE
	Sbox += '}'
	return (Sbox)

if __name__ == '__main__':
	output_orwg_go()
