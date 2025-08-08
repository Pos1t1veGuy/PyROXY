import os
parameters = ' --'.join(open('profile.pyroxy', 'r').read().split('\n'))
os.system('python console_client.py --' + parameters)