try:
    import os, sys

    target = 'client.exe'
    if sys.argv[-1] == '--py':
        target = 'python client.py'

    if os.path.isfile('profile.pyroxy'):
        print('running with profile config...')
        parameters = ' --'.join(open('profile.pyroxy', 'r').read().split('\n'))
        os.system(f'{target} --{parameters}')
    else:
        input('ERROR: profile config not found, looking for a "profile.proxy" file. Press ENTER to close the program...')

except KeyboardInterrupt:
    pass