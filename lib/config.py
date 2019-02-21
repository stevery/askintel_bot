'''
Note: this is an example configuration file (the API key does not actually work).
Before using VxApi, please copy this file, name it 'config.py` and then put in the same directory as the current one.
'''


def get_config():
    import json
    import sys
    try:
        json_data=open("../lib/api.json").read()
    except:
        print("If you run easyintell You need set api.json first")
        sys.exit(0)
    apis = json.loads(json_data)
    return {
        "api_key": apis["hybrid"]["api_key"],
        "server": apis["hybrid"]["server"]
    }
