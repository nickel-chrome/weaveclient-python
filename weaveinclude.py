import re

def trim_str(string, internal=False):
	if internal:
		pat = re.compile('\s+')
		return pat.sub('', string)
	else:
		return string.trim()


class WeaveException(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)
