from pyramid.view import view_config
from .aes_rc6 import AES as AES_RC6, rc6_encrypt, rc6_decrypt
from time import time
from datetime import datetime
import base64


@view_config(route_name='home', renderer='templates/mytemplate.jinja2')
def home(request):
	return {'project': 'odex-web'}


@view_config(route_name='main', renderer='templates/main.jinja2')
def main(request):
	return {'project': 'odex-web'}


@view_config(route_name='encrypt_decrypt', renderer='templates/encdec.jinja2')
def encrypt_decrypt_view(request):
	invalid_message = params_check(request.params)
	
	if invalid_message != "":
		return {'invalid_message': invalid_message}
	
	input_text = ""
	key = ""
	result = ""
	args = []
	method = None
	operation = ""
	
	try:
		
		if request.params['text_type'] == 'hex':
			input_text = bytes.fromhex(request.params['input_text'])
		else:
			input_text = request.params['input_text'].encode()
		
		if request.params['key_type'] == 'hex':
			key = request.params['key'].decode('hex').encode()
		else:
			key = request.params['key'].encode()
		
		key = key_pad(key)
		
		if request.params['function'] == 'aes-rc6':
			args = [key, input_text, True]
		else:
			args = [key, input_text]
		
		if request.params['operation'] == 'encrypt':
			operation = 'Encrypt'
			method = encrypt
			
			if request.params['function'] == 'rc6':
				method = encrypt_rc6
			
		else:
			operation = 'Decrypt'
			method = decrypt
			
			if request.params['function'] == 'rc6':
				method = decrypt_rc6
	
		result = method(*args)
	except Exception as e:
		invalid_message = str(e)
		return {'invalid_message': invalid_message, 'operation' : operation}

	readable_text = ""

	try:
		#readable_text = result[0].decode()
		pass
	except Exception as e:
		readable_text = str(e)

	return {'invalid_message': invalid_message, 'result' : result[0].hex(), 'operation' : operation, 'readable_text' : base64.b64encode(result[0]).decode(), 'time_elapse' : (result[1]), 'trace' : result[2].split('\n')}

def key_pad(key):
	allowed_key_len = [16, 24, 32]
	
	if len(key) in allowed_key_len or len(key) > 32:
		return key
	
	for each_ in allowed_key_len:
		if len(key) < each_:
			remaining = each_ - len(key)
			return ( key + (remaining * b'\0') )
	
def params_check(request_params):
	message = ""
	
	param_to_check = ['input_text', 'text_type', 'function', 'key', 'key_type', 'operation']
	
	for each_param in param_to_check:
		message += param_invalid_message(each_param, request_params)

	return message

def param_invalid_message(each_param, request_params):
	message = ""
	
	if (each_param in request_params):
		if (request_params['input_text'] == ""):
			message += "Param '{}' is empty<br/>".format(each_param)
	else:
		message += "Need param '{}'<br/>".format(each_param)
	
	return message

def create_blocks(text):
	block_num = int (len(text) / 16)
	remaining = len(text) % 16
	
	blocks = []
	
	for i in range(0, block_num):
		start_i = i*16;
		end_i = start_i + 16;
		
		blocks.append( text[start_i : end_i] )
	
	if remaining:
		remaining_text = text[(0 - remaining):]
		padding = ( (16 - remaining) * b'\0') # null padding
		blocks.append( remaining_text + padding )
	
	return blocks

def encrypt(key, text, rc6_enabled = False):
	time_start = time()

	if (type(key) is not bytes or type(text) is not bytes):
		raise Exception("Key and text must be bytes")
		return

	# ini mode ECB
	aes_rc6 = AES_RC6(key)
	
	blocks = create_blocks(text)
	ciphertext = b''
	trace = ''
	
	for each_block in blocks:
		result = aes_rc6.encrypt_block( each_block, rc6_enabled = rc6_enabled, trace_enabled = True )
		ciphertext += result[0]
		trace += result[1]
	
	time_end = time()
	time_elapsed = int(round( (time_end - time_start) * 1000) )
	
	return [ciphertext, time_elapsed, trace]
	

def decrypt(key, cipher, rc6_enabled = False):
	time_start = time()
	
	if (type(key) is not bytes or type(cipher) is not bytes):
		raise Exception("Key and text must be bytes")
		return
	
	# ini mode ECB
	aes_rc6 = AES_RC6(key)
	
	blocks = create_blocks(cipher)
	text = b''
	trace = ''
	
	for each_block in blocks:
		result = aes_rc6.decrypt_block( each_block, rc6_enabled = rc6_enabled, trace_enabled = True) 
		text += result[0]
		trace += result[1]
	
	time_end = time()
	time_elapsed = int(round( (time_end - time_start) * 1000) )
	
	return [(text.partition(b'\0')[0]), time_elapsed, trace]

def encrypt_rc6(key, text):
	time_start = time()

	if (type(key) is not bytes or type(text) is not bytes):
		raise Exception("Key and text must be bytes")
		return

	blocks = create_blocks(text)
	ciphertext = b''
	trace = ''
	
	for each_block in blocks:
		ciphertext +=  bytes.fromhex( rc6_encrypt(each_block.hex().upper(), key.hex().upper() ) )
	
	time_end = time()
	time_elapsed = int(round( (time_end - time_start) * 1000) )
	
	return [ciphertext, time_elapsed, trace]

def decrypt_rc6(key, text):
	time_start = time()

	if (type(key) is not bytes or type(text) is not bytes):
		raise Exception("Key and text must be bytes")
		return

	blocks = create_blocks(text)
	text = b''
	trace = ''
	
	for each_block in blocks:
		text +=  bytes.fromhex( rc6_decrypt(each_block.hex().upper(), key.hex().upper() ) )
	
	time_end = time()
	time_elapsed = int(round( (time_end - time_start) * 1000) )
	
	return [(text.partition(b'\0')[0]), time_elapsed, trace]