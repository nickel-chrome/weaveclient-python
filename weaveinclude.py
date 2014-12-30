import re

from urlparse import urlparse


def trim_str(string, internal=False):
	if internal:
		pat = re.compile('\s+')
		return pat.sub('', string)
	else:
		return string.trim()


def parse_normalized_url(url):
    """Parse url and set port."""
    url_parts = urlparse(url)
    url_dict = {
        'scheme': url_parts.scheme,
        'hostname': url_parts.hostname,
        'port': url_parts.port,
        'path': url_parts.path,
        'resource': url_parts.path,
        'query': url_parts.query,
    }
    if len(url_dict['query']) > 0:
        url_dict['resource'] = '%s?%s' % (url_dict['resource'],
                                          url_dict['query'])

    if url_parts.port is None:
        if url_parts.scheme == 'http':
            url_dict['port'] = 80
        elif url_parts.scheme == 'https':
            url_dict['port'] = 443
    return url_dict


class WeaveException(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)
