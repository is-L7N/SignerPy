def dicts(url):
    url, param_str = url.split('?', 1)
    paramd = dict(p.split('=') for p in param_str.split('&'))
    params = "{\n"
    for k, v in paramd.items():
        params += f'    "{k}": "{v}",\n'
    params += "}"
    return params
    
    
    