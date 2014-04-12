# -*- coding: utf-8 -*-
import sys, re, os

rx_aes = re.compile("({AES}[^<]*)[<]")
rx_3des = re.compile("\"({3DES}[^\"]*)\"")

algorithm_matches = [rx_3des, rx_aes]

with open("config.xml", "r") as xml_file:
	for line in xml_file:
		for possible_algo in algorithm_matches:
			found = possible_algo.search(line)
			if found:
				encrypted_value = found.group(1)
				print encrypted_value
				decrypted_value = os.popen("java -jar wlsconfr.jar \"%s\"" % encrypted_value).readlines()
				print encrypted_value, "-->", decrypted_value

